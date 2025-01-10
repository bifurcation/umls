use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::protocol::*;
use crate::syntax::*;
use crate::tree_math::*;
use crate::{make_storage, mls_enum, mls_struct, mls_struct_serialize, serialize};

use heapless::Vec;
use rand::Rng;
use rand_core::CryptoRngCore;

mod consts {
    pub use crate::protocol::consts::MAX_GROUP_SIZE;
    pub use crate::protocol::consts::MAX_TREE_DEPTH;

    pub const MAX_NODE_WIDTH: usize = 2 * MAX_GROUP_SIZE - 1;
    pub const ROOT_NODE_INDEX: usize = MAX_GROUP_SIZE - 1;
}

type PathSecretList = Vec<Option<HashOutput>, { consts::MAX_TREE_DEPTH }>;
type PathSecretListView<'a> = Vec<Option<HashOutputView<'a>>, { consts::MAX_TREE_DEPTH }>;

mls_struct! {
    RatchetTreePriv + RatchetTreePrivView,
    encryption_priv: HpkePrivateKey + HpkePrivateKeyView,
    path_secrets: PathSecretList + PathSecretListView,
}

impl RatchetTreePriv {
    pub fn new(
        ratchet_tree: &RatchetTree,
        my_index: LeafIndex,
        sender: LeafIndex,
        path_secret: OptionalPathSecretView,
        encryption_priv: HpkePrivateKeyView,
    ) -> Result<Self> {
        let mut path_secrets = PathSecretList::default();

        if let Some(path_secret) = path_secret {
            let mut path_secret = path_secret.to_object();
            let path = ratchet_tree.resolve_path(sender);
            path_secrets.resize_default(path.len()).unwrap();

            for (ps_mut, (n, res)) in path_secrets.iter_mut().zip(path.iter()) {
                if res.is_empty() {
                    continue;
                }

                *ps_mut = Some(path_secret.clone());
                path_secret = crypto::derive_secret(path_secret.as_view().into(), b"path");
            }
        }

        Ok(Self {
            encryption_priv: encryption_priv.to_object(),
            path_secrets,
        })
    }

    pub fn commit_secret(&self) -> Result<HashOutput> {
        let path_secret = self
            .path_secrets
            .last()
            .ok_or(Error("No root path secret available"))?
            .as_ref()
            .ok_or(Error("No root path secret available"))?;
        Ok(crypto::derive_secret(path_secret.as_view().into(), b"path"))
    }
}

type Resolution = Vec<NodeIndex, { consts::MAX_GROUP_SIZE / 2 }>;
type ResolutionPath = Vec<(NodeIndex, Resolution), { consts::MAX_TREE_DEPTH }>;

type UnmergedLeavesList = Vec<LeafIndex, { consts::MAX_GROUP_SIZE / 2 }>;
type UnmergedLeavesListView<'a> = Vec<LeafIndexView<'a>, { consts::MAX_GROUP_SIZE / 2 }>;

mls_struct! {
    ParentNode + ParentNodeView,
    public_key: HpkePublicKey + HpkePublicKeyView,
    parent_hash: HashOutput + HashOutputView,
    unmerged_leaves: UnmergedLeavesList + UnmergedLeavesListView,
}

mls_enum! {
    u8 => Node + NodeView,
    1 => Leaf(LeafNode + LeafNodeView),
    2 => Parent(ParentNode + ParentNodeView),
}

impl Node {
    fn encryption_key(&self) -> &HpkePublicKey {
        match self {
            Node::Leaf(leaf) => &leaf.encryption_key,
            Node::Parent(parent) => &parent.public_key,
        }
    }
}

type OptionalNode = Option<Node>;
type OptionalNodeView<'a> = Option<NodeView<'a>>;

// XXX(RLB) This is a wasteful in-memory representation, since every Node takes up the full
// LeafNode worth of memory, even though a ParentNode is much smaller.  We could optimize this by
// telling the compiler which nodes are leaf / parent nodes, for example:
//
// * Instead of a single NodeList, store a Vec<Option<LeafNode>> and a Vec<Option<ParentNode>>
// * For referencing nodes by NodeIndex, make the translation in RatchetTree::node_at
// * Write custom Serialize and Deserialize implementations that alternate as appropriate
type NodeList = Vec<OptionalNode, { 2 * consts::MAX_GROUP_SIZE - 1 }>;
type NodeListView<'a> = Vec<OptionalNodeView<'a>, { 2 * consts::MAX_GROUP_SIZE - 1 }>;

mls_struct! {
    RatchetTree + RatchetTreeView,
    nodes: NodeList + NodeListView,
}

impl<'a> RatchetTreeView<'a> {
    pub fn size(&self) -> LeafCount {
        NodeCount(self.nodes.len()).into()
    }
}

impl RatchetTree {
    fn node_at(&self, i: NodeIndex) -> &OptionalNode {
        &self.nodes[i.0]
    }

    fn node_at_mut(&mut self, i: NodeIndex) -> &mut OptionalNode {
        &mut self.nodes[i.0]
    }

    pub fn size(&self) -> LeafCount {
        NodeCount(self.nodes.len()).into()
    }

    pub fn find(&self, leaf_node: LeafNodeView) -> Option<LeafIndex> {
        let target = Some(NodeView::Leaf(leaf_node));
        self.nodes
            .iter()
            .step_by(2)
            .position(|n| n.as_view() == target)
            .map(|i| LeafIndex(i as u32))
    }

    pub fn leaf_node_at(&self, index: LeafIndex) -> Option<LeafNodeView> {
        self.node_at(index.into()).as_ref().and_then(|n| match n {
            Node::Leaf(leaf_node) => Some(leaf_node.as_view()),
            Node::Parent(_) => None,
        })
    }

    // TODO(RLB) Add leaf to unmerged_leaves in any non-blank parent nodes
    pub fn add_leaf(&mut self, leaf_node: LeafNode) -> Result<()> {
        // Assign to a blank leaf node if one exists
        let blank = self
            .nodes
            .iter()
            .step_by(2)
            .position(|n| n.is_none())
            .map(|i| LeafIndex(i as u32));
        let joiner_leaf = if let Some(index) = blank {
            index
        } else {
            let next_leaf = if self.nodes.is_empty() {
                LeafIndex(0)
            } else {
                LeafIndex((self.nodes.len() as u32 + 1) / 2)
            };

            self.expand()?;
            next_leaf
        };

        self.blank_path(joiner_leaf);
        *self.node_at_mut(joiner_leaf.into()) = Some(Node::Leaf(leaf_node));

        let mut curr: NodeIndex = joiner_leaf.into();
        while let Some(parent) = curr.parent(self.size().into()) {
            curr = parent;

            let maybe_parent_node = self.node_at_mut(parent).as_mut();
            if maybe_parent_node.is_none() {
                continue;
            }

            let Some(Node::Parent(parent_node)) = maybe_parent_node else {
                return Err(Error("Misconfigured tree"));
            };

            parent_node.unmerged_leaves.push(joiner_leaf).unwrap();
        }

        Ok(())
    }

    pub fn remove_leaf(&mut self, removed: LeafIndex) {
        self.blank_path(removed);
        self.truncate()
    }

    pub fn root_hash(&self) -> Result<HashOutput> {
        self.hash(self.size().root())
    }

    fn hash(&self, index: NodeIndex) -> Result<HashOutput> {
        if index.is_leaf() {
            self.leaf_hash(index)
        } else {
            self.parent_hash(index)
        }
    }

    fn leaf_hash(&self, index: NodeIndex) -> Result<HashOutput> {
        // struct {
        //     uint32 leaf_index;
        //     optional<LeafNode> leaf_node;
        // } LeafNodeHashInput;
        let mut h = Hash::new();

        let leaf_index = LeafIndex::try_from(index)?;
        leaf_index.serialize(&mut h)?;

        let optional_leaf = self.node_at(index).as_ref().and_then(|node| match node {
            Node::Leaf(leaf_node) => Some(leaf_node),
            Node::Parent(_) => unreachable!(),
        });
        optional_leaf.serialize(&mut h)?;

        Ok(h.finalize())
    }

    fn parent_hash(&self, index: NodeIndex) -> Result<HashOutput> {
        // struct {
        //     optional<ParentNode> parent_node;
        //     opaque left_hash<V>;
        //     opaque right_hash<V>;
        // } ParentNodeHashInput;
        let mut h = Hash::new();

        let optional_parent = self.node_at(index).as_ref().and_then(|node| match node {
            Node::Leaf(_) => unreachable!(),
            Node::Parent(parent_node) => Some(parent_node),
        });
        optional_parent.serialize(&mut h)?;

        self.hash(index.left().unwrap())?.serialize(&mut h)?;
        self.hash(index.right().unwrap())?.serialize(&mut h)?;

        Ok(h.finalize())
    }

    fn expand(&mut self) -> Result<()> {
        let width = 2 * self.nodes.len() + 1;
        self.nodes
            .resize_default(width)
            .map_err(|_| Error("Resize error"))
    }

    fn truncate(&mut self) {
        let mut start = self.nodes.len() / 2;
        let mut end = self.nodes.len();
        while start > 0 && self.nodes[start..end].iter().all(|n| n.is_none()) {
            end = start;
            start /= 2;
        }

        self.nodes.resize_default(end).unwrap()
    }

    fn blank_path(&mut self, leaf_index: LeafIndex) {
        let node_index: NodeIndex = leaf_index.into();
        *self.node_at_mut(node_index) = None;
        let mut p = node_index.parent(self.size().into());
        while let Some(index) = p {
            *self.node_at_mut(index) = None;
            p = index.parent(self.size().into());
        }
    }

    pub fn update_direct_path(
        &mut self,
        rng: &mut (impl CryptoRngCore + Rng),
        from: LeafIndex,
        signature_priv: SignaturePrivateKeyView,
    ) -> Result<(RatchetTreePriv, UpdatePath)> {
        let path = self.resolve_path(from);

        // Generate path secrets
        let mut path_secret = HashOutput(Opaque::random(rng));
        let path_secrets: PathSecretList = path
            .iter()
            .map(|(_n, res)| {
                if res.is_empty() {
                    None
                } else {
                    path_secret = crypto::derive_secret(path_secret.as_view().into(), b"path");
                    Some(path_secret.clone())
                }
            })
            .collect();

        // Compute the corresponding public keys
        let nodes: Result<UpdatePathNodeList> = path_secrets
            .iter()
            .filter_map(|ps| ps.as_ref())
            .map(|ps| {
                let node_secret = crypto::derive_secret(path_secret.as_view().into(), b"node");
                let (_, encryption_key) = crypto::derive_hpke(node_secret.as_view())?;
                Ok(UpdatePathNode {
                    encryption_key,
                    encrypted_path_secret: Default::default(),
                })
            })
            .collect();
        let nodes = nodes?;

        // Re-sign the leaf node
        let Some(Node::Leaf(leaf_node)) = self.node_at_mut(from.into()).as_mut() else {
            return Err(Error("Encap from blank leaf"));
        };

        let (encryption_priv, encryption_key) = crypto::generate_hpke(rng)?;
        leaf_node.tbs.encryption_key = encryption_key;
        // TODO(RLB): Add parent hash here
        leaf_node.tbs.leaf_node_source = LeafNodeSource::Commit(Default::default());
        leaf_node.re_sign(signature_priv)?;

        // Assemble the return values
        let ratchet_tree_priv = RatchetTreePriv {
            encryption_priv,
            path_secrets,
        };

        let update_path = UpdatePath {
            leaf_node: leaf_node.clone(),
            nodes,
        };

        Ok((ratchet_tree_priv, update_path))
    }

    pub fn encrypt_path_secrets(
        &self,
        rng: &mut (impl CryptoRngCore + Rng),
        from: LeafIndex,
        group_context: &GroupContext,
        ratchet_tree_priv: &RatchetTreePriv,
        mut update_path: UpdatePath,
    ) -> Result<UpdatePath> {
        let path = self.resolve_path(from);
        let group_context = serialize!(GroupContext, group_context);

        println!("encap ctx = {}", hex::encode(&group_context));

        let filtered_priv = ratchet_tree_priv
            .path_secrets
            .iter()
            .filter_map(|ps| ps.as_ref());
        let resolutions = path.iter().map(|(_, res)| res);
        let encrypted_path_secret = update_path
            .nodes
            .iter_mut()
            .map(|n| &mut n.encrypted_path_secret);
        for ((ps, res), enc) in filtered_priv.zip(resolutions).zip(encrypted_path_secret) {
            let raw_path_secret = Raw::try_from(ps.as_ref())?;
            for n in res.iter() {
                let encryption_node = self
                    .node_at(*n)
                    .as_ref()
                    .ok_or(Error("Blank node in resolution"))?;

                let encryption_key = encryption_node.encryption_key().as_view();
                let encrypted_path_secret = EncryptedPathSecret::seal(
                    rng,
                    raw_path_secret.clone(),
                    encryption_key,
                    &group_context,
                )?;

                enc.push(encrypted_path_secret).unwrap();
            }
        }

        Ok(update_path)
    }

    pub fn decap(
        &mut self,
        ratchet_tree_priv: &mut RatchetTreePriv,
        update_path: UpdatePathView,
        from: LeafIndex,
        to: LeafIndex,
        group_context: &GroupContext,
    ) -> Result<()> {
        let path = self.resolve_path(from);
        let group_context = serialize!(GroupContext, group_context);

        println!("decap ctx = {}", hex::encode(&group_context));

        // Identify the path secret to decrypt, and where in the path to implant it.
        let path_index = path
            .iter()
            .position(|(n, _res)| n.is_above_or_eq(to))
            .unwrap();

        let update_path_index = path
            .iter()
            .filter(|(_n, res)| !res.is_empty())
            .position(|(n, _res)| n.is_above_or_eq(to))
            .unwrap();

        let res_index = path[path_index]
            .1
            .iter()
            .position(|n| n.is_above_or_eq(to))
            .unwrap();

        // The key to decrypt with is the first one in our direct path below the overlap node.  The
        // overlap node is at position `path_index`, so we start there and search backwards.  If no
        // path secret is found, we use the leaf private key.
        let path_encryption_priv = ratchet_tree_priv
            .path_secrets
            .iter()
            .take(path_index)
            .rev()
            .find(|ps| ps.is_some())
            .map(|ps| {
                let decrypt_node_secret =
                    crypto::derive_secret(ps.as_ref().unwrap().as_view().into(), b"node");
                let (encryption_priv, encryption_pub) =
                    crypto::derive_hpke(decrypt_node_secret.as_view())?;
                Ok(encryption_priv)
            })
            .transpose()?;

        let encryption_priv_view = if let Some(encryption_priv) = path_encryption_priv.as_ref() {
            encryption_priv.as_view()
        } else {
            ratchet_tree_priv.encryption_priv.as_view()
        };

        // Decrypt the path secret
        let encrypted_path_secret =
            update_path.nodes[update_path_index].encrypted_path_secret[res_index].clone();
        let raw_path_secret = encrypted_path_secret.open(encryption_priv_view, &group_context)?;
        let mut path_secret = HashOutput(Opaque::from(raw_path_secret));

        // Grow / shrink the path to accommodate changes in the size of the tree
        ratchet_tree_priv
            .path_secrets
            .resize_default(path.len())
            .unwrap();

        // Implant the path secret and hash to the end
        ratchet_tree_priv.path_secrets[path_index] = Some(path_secret.clone());
        let start = path_index + 1;
        let end = ratchet_tree_priv.path_secrets.len();
        for i in start..end {
            if path[i].1.is_empty() {
                continue;
            }

            path_secret = crypto::derive_secret(path_secret.as_view().into(), b"path");
            ratchet_tree_priv.path_secrets[i] = Some(path_secret.clone());
        }

        Ok(())
    }

    pub fn merge(&mut self, update_path: &UpdatePath, from: LeafIndex) {
        let path = self.resolve_path(from);
        let curr = NodeIndex::from(from);
        let width = NodeCount::from(self.size());

        let filtered_path = path
            .iter()
            .filter(|(_, res)| !res.is_empty())
            .map(|(n, _)| n);
        let keys = update_path.nodes.iter().map(|n| n.encryption_key.clone());
        for (n, public_key) in filtered_path.zip(keys) {
            *self.node_at_mut(*n) = Some(Node::Parent(ParentNode {
                public_key,
                parent_hash: Default::default(), // TODO(RLB) Set parent hash
                unmerged_leaves: Default::default(),
            }));
        }

        *self.node_at_mut(NodeIndex::from(from)) = Some(Node::Leaf(update_path.leaf_node.clone()));
    }

    fn resolve_path(&self, leaf_node: LeafIndex) -> ResolutionPath {
        let mut path = Vec::new();
        let mut curr = NodeIndex::from(leaf_node);
        let width = self.size().into();

        while let Some(parent) = curr.parent(width) {
            let cc = parent.copath_child(leaf_node).unwrap();
            path.push((parent, self.resolve(cc))).unwrap();
            curr = parent;
        }

        path
    }

    fn resolve(&self, subtree_root: NodeIndex) -> Vec<NodeIndex, { consts::MAX_GROUP_SIZE / 2 }> {
        let mut res = Vec::new();

        match self.node_at(subtree_root) {
            // The resolution of a non-blank node comprises the node itself, followed by its list of
            // unmerged leaves, if any.
            Some(Node::Leaf(node)) => res.push(subtree_root).unwrap(),
            Some(Node::Parent(node)) => {
                res.push(subtree_root).unwrap();
                res.extend(node.unmerged_leaves.iter().map(|&i| i.into()));
            }

            // The resolution of a blank leaf node is the empty list.
            None if subtree_root.is_leaf() => {}

            // The resolution of a blank intermediate node is the result of concatenating the
            // resolution of its left child with the resolution of its right child, in that
            // order.todo!()
            None => {
                let left = subtree_root.left().unwrap();
                res.extend_from_slice(&self.resolve(left)).unwrap();

                let right = subtree_root.right().unwrap();
                res.extend_from_slice(&self.resolve(right)).unwrap();
            }
        }

        res
    }
}
