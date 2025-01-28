use crate::common::{Error, Result};
use crate::crypto::{
    Crypto, DependentSizes, Hash, HashOutput, HpkeEncrypt, HpkePrivateKey, HpkePublicKey,
    Initializers, RawHashOutput, SignaturePrivateKey,
};
use crate::io::{CountWriter, Read, Write};
use crate::protocol::{
    GroupContext, LeafIndex, LeafNode, LeafNodeSource, PathSecret, RawPathSecret, TreeHash,
    UpdatePath, UpdatePathNode,
};
use crate::stack;
use crate::syntax::{Deserialize, Materialize, Nil, Serialize, Varint};
use crate::tree_math::{LeafCount, NodeCount, NodeIndex};

use heapless::{FnvIndexMap, Vec};
use itertools::Itertools;
use rand::CryptoRng;

mod consts {
    pub use crate::protocol::consts::MAX_GROUP_SIZE;
    pub use crate::protocol::consts::MAX_RESOLUTION_SIZE;
    pub use crate::protocol::consts::MAX_TREE_DEPTH;
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct RatchetTreePriv<C: Crypto> {
    pub encryption_priv: HpkePrivateKey<C>,
    pub path_secrets: Vec<Option<PathSecret<C>>, { consts::MAX_TREE_DEPTH }>,
    pub commit_secret: HashOutput<C>,
}

impl<C: Crypto> RatchetTreePriv<C> {
    pub fn new(
        ratchet_tree: &RatchetTree<C>,
        my_index: LeafIndex,
        sender: LeafIndex,
        path_secret: Option<PathSecret<C>>,
        encryption_priv: HpkePrivateKey<C>,
    ) -> Result<Self> {
        stack::update();
        let mut path_secrets = Vec::default();

        if let Some(path_secret) = path_secret {
            let mut path_secret = path_secret;
            let path = ratchet_tree.resolve_path(sender);
            path_secrets.resize_default(path.len()).unwrap();

            for (ps_mut, (n, res)) in path_secrets.iter_mut().zip(path.iter()) {
                if res.is_empty() || !n.is_above_or_eq(my_index) {
                    continue;
                }

                *ps_mut = Some(path_secret.clone());
                path_secret = PathSecret(C::derive_secret(&path_secret.0, b"path"));
            }
        }

        Ok(Self {
            encryption_priv,
            path_secrets,
            commit_secret: Default::default(),
        })
    }

    pub fn blank_path(&mut self, my_index: LeafIndex, removed: LeafIndex, width: NodeCount) {
        let mut curr: Option<NodeIndex> = Some(my_index.into());
        curr = curr.unwrap().parent(width);

        for (i, ps) in self.path_secrets.iter_mut().enumerate() {
            match curr {
                None => {
                    self.path_secrets.truncate(i);
                    break;
                }
                Some(parent) => {
                    if parent.is_above_or_eq(removed) {
                        *ps = None;
                    }
                    curr = parent.parent(width);
                }
            }
        }
    }

    pub fn commit_secret(&self) -> HashOutput<C> {
        stack::update();
        self.commit_secret.clone()
    }

    pub fn consistent(&self, ratchet_tree: &RatchetTree<C>, my_index: LeafIndex) -> bool {
        stack::update();
        let width: NodeCount = ratchet_tree.size().into();
        let encryption_key = C::hpke_priv_to_pub(&self.encryption_priv);
        if ratchet_tree
            .leaf_node_at(my_index)
            .as_ref()
            .unwrap()
            .tbs
            .encryption_key
            != encryption_key
        {
            return false;
        }

        let mut i = 0;
        let mut curr = NodeIndex::from(my_index).parent(width);
        while let Some(parent) = curr {
            let parent_index = ParentIndex::try_from(parent).unwrap();
            let parent_node = ratchet_tree.parent_node_at(parent_index);
            let path_secret = self.path_secrets[i].as_ref();

            match (path_secret, parent_node) {
                (Some(_), None) => return false,
                (Some(path_secret), Some(node)) => {
                    let node_secret = C::derive_secret(&path_secret.0, b"node");
                    let (_, priv_key) = C::hpke_derive(&node_secret).unwrap();

                    if node.public_key != priv_key {
                        return false;
                    }
                }
                (None, Some(node)) => {
                    if !node.unmerged_leaves.contains(&my_index) {
                        return false;
                    }
                }
                (None, None) => {}
            }

            curr = parent.parent(width);
            i += 1;
        }

        true
    }
}

type Resolution = Vec<NodeIndex, { consts::MAX_RESOLUTION_SIZE }>;
type ResolutionPath = Vec<(NodeIndex, Resolution), { consts::MAX_TREE_DEPTH }>;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct ParentNode<C: Crypto> {
    public_key: HpkePublicKey<C>,
    parent_hash: HashOutput<C>,
    unmerged_leaves: Vec<LeafIndex, { consts::MAX_RESOLUTION_SIZE }>,
}

#[derive(Serialize, Deserialize)]
#[discriminant = "u8"]
enum Node<C: Crypto> {
    #[discriminant = "1"]
    Leaf(LeafNode<C>),

    #[discriminant = "2"]
    Parent(ParentNode<C>),
}

#[derive(Copy, Clone)]
struct ParentIndex(usize);

impl TryFrom<NodeIndex> for ParentIndex {
    type Error = Error;

    fn try_from(val: NodeIndex) -> Result<Self> {
        stack::update();
        if val.is_leaf() {
            return Err(Error("Malformed index"));
        }

        Ok(Self((val.0 - 1) / 2))
    }
}

// TODO(RLB): Verify that this is the correct max size.
type TreeHashCache<C> = FnvIndexMap<(NodeIndex, usize), HashOutput<C>, { consts::MAX_GROUP_SIZE }>;

#[derive(Default, Clone, PartialEq, Debug)]
pub struct RatchetTree<C: Crypto> {
    leaf_nodes: Vec<Option<LeafNode<C>>, { consts::MAX_GROUP_SIZE }>,
    parent_nodes: Vec<Option<ParentNode<C>>, { consts::MAX_GROUP_SIZE - 1 }>,
}

impl<C: Crypto> Serialize for RatchetTree<C> {
    const MAX_SIZE: usize =
        Self::MAX_LENGTH_HEADER_SIZE + Self::MAX_LEAF_NODES_SIZE + Self::MAX_PARENT_NODES_SIZE;

    // Serialize Vec<Option<Node>> without materializing it
    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        stack::update();
        let mut counter = CountWriter::default();
        for node in self.node_iter() {
            node.serialize(&mut counter)?;
        }

        Varint(counter.len()).serialize(writer)?;

        for node in self.node_iter() {
            node.serialize(writer)?;
        }

        Ok(())
    }
}

impl<C: Crypto> Deserialize for RatchetTree<C> {
    fn deserialize(reader: &mut impl Read) -> Result<Self> {
        stack::update();
        let len = Varint::deserialize(reader)?;

        let mut content = reader.take(len.0)?;
        let mut leaf_nodes = Vec::new();
        let mut parent_nodes = Vec::new();
        let mut leaf = true;
        while !content.is_empty() {
            let node = Option::<Node<C>>::deserialize(&mut content)?;
            match node {
                Some(Node::Leaf(node)) if leaf => leaf_nodes.push(Some(node)).unwrap(),
                None if leaf => leaf_nodes.push(None).unwrap(),
                Some(Node::Parent(node)) if !leaf => parent_nodes.push(Some(node)).unwrap(),
                None if !leaf => parent_nodes.push(None).unwrap(),
                _ => return Err(Error("Malformed ratchet tree")),
            }

            leaf = !leaf;
        }

        if parent_nodes.len() != leaf_nodes.len() - 1 {
            return Err(Error("Malformed ratchet tree"));
        }

        // Pad leaf count to a power of two
        while leaf_nodes.len().count_ones() > 1 {
            leaf_nodes.push(None).unwrap();
            parent_nodes.push(None).unwrap();
        }

        Ok(Self {
            leaf_nodes,
            parent_nodes,
        })
    }
}

impl<C: Crypto> RatchetTree<C> {
    const MAX_LEAF_NODES_SIZE: usize = Option::<LeafNode<C>>::MAX_SIZE * consts::MAX_GROUP_SIZE;
    const MAX_PARENT_NODES_SIZE: usize =
        Option::<ParentNode<C>>::MAX_SIZE * (consts::MAX_GROUP_SIZE - 1);
    const MAX_LENGTH_HEADER_SIZE: usize =
        Varint::size(Self::MAX_LEAF_NODES_SIZE + Self::MAX_PARENT_NODES_SIZE);

    fn node_iter(&self) -> impl Iterator<Item = Option<Node<C>>> + use<'_, C> {
        stack::update();
        let n_trailing_blanks = self
            .leaf_nodes
            .iter()
            .rev()
            .position(core::option::Option::is_some)
            .unwrap();
        let n_nodes = 2 * (self.leaf_nodes.len() - n_trailing_blanks) - 1;

        let leaf_nodes = self
            .leaf_nodes
            .iter()
            .map(|n| n.as_ref().map(|leaf| Node::Leaf(leaf.clone())));
        let parent_nodes = self
            .parent_nodes
            .iter()
            .map(|n| n.as_ref().map(|parent| Node::Parent(parent.clone())));

        // Interleave nodes, and truncate trailing blank nodes
        leaf_nodes.interleave(parent_nodes).take(n_nodes)
    }

    pub fn leaf_node_at(&self, i: LeafIndex) -> Option<&LeafNode<C>> {
        stack::update();
        self.leaf_nodes[i.0 as usize].as_ref()
    }

    fn parent_node_at(&self, i: ParentIndex) -> Option<&ParentNode<C>> {
        stack::update();
        self.parent_nodes[i.0].as_ref()
    }

    fn leaf_node_at_mut(&mut self, i: LeafIndex) -> &mut Option<LeafNode<C>> {
        stack::update();
        &mut self.leaf_nodes[i.0 as usize]
    }

    fn parent_node_at_mut(&mut self, i: ParentIndex) -> &mut Option<ParentNode<C>> {
        stack::update();
        &mut self.parent_nodes[i.0]
    }

    fn encryption_key_at(&self, n: NodeIndex) -> Option<&HpkePublicKey<C>> {
        stack::update();
        // TODO(RLB) Find a way to do this with match, maybe by making NodeIndex an enum?
        if let Ok(n) = LeafIndex::try_from(n) {
            self.leaf_node_at(n)
                .as_ref()
                .map(|node| &node.tbs.encryption_key)
        } else {
            let n = ParentIndex::try_from(n).unwrap();
            self.parent_node_at(n).as_ref().map(|node| &node.public_key)
        }
    }

    fn parent_hash_at(&self, n: NodeIndex) -> Option<HashOutput<C>> {
        stack::update();
        // TODO(RLB) Find a way to do this with match, maybe by making NodeIndex an enum?
        if let Ok(n) = LeafIndex::try_from(n) {
            self.leaf_node_at(n)
                .as_ref()
                .and_then(|node| match &node.tbs.leaf_node_source {
                    LeafNodeSource::Commit(parent_hash) => Some(parent_hash.clone()),
                    _ => None,
                })
        } else {
            let n = ParentIndex::try_from(n).unwrap();
            self.parent_node_at(n)
                .as_ref()
                .map(|node| node.parent_hash.clone())
        }
    }

    pub fn size(&self) -> LeafCount {
        stack::update();
        LeafCount(self.leaf_nodes.len())
    }

    pub fn find(&self, target: &LeafNode<C>) -> Option<LeafIndex> {
        stack::update();
        let target = Some(target.clone());
        self.leaf_nodes
            .iter()
            .position(|n| *n == target)
            .map(|i| LeafIndex(i as u32))
    }

    pub fn add_leaf(&mut self, leaf_node: LeafNode<C>) -> Result<LeafIndex> {
        stack::update();
        // Assign to a blank leaf node if one exists
        let blank = self
            .leaf_nodes
            .iter()
            .position(core::option::Option::is_none)
            .map(|i| LeafIndex(i as u32));
        let joiner_leaf = if let Some(index) = blank {
            index
        } else {
            let next_leaf = if self.leaf_nodes.is_empty() {
                LeafIndex(0)
            } else {
                LeafIndex(self.leaf_nodes.len() as u32)
            };

            self.expand()?;
            next_leaf
        };

        *self.leaf_node_at_mut(joiner_leaf) = Some(leaf_node);

        let mut curr: NodeIndex = joiner_leaf.into();
        while let Some(parent) = curr.parent(self.size().into()) {
            curr = parent;

            let maybe_parent_node = self.parent_node_at_mut(parent.try_into()?).as_mut();
            if maybe_parent_node.is_none() {
                continue;
            }

            let Some(parent_node) = maybe_parent_node else {
                return Err(Error("Misconfigured tree"));
            };

            parent_node.unmerged_leaves.push(joiner_leaf).unwrap();
        }

        Ok(joiner_leaf)
    }

    pub fn remove_leaf(&mut self, removed: LeafIndex) -> Result<()> {
        stack::update();
        if self.leaf_node_at(removed).is_none() {
            return Err(Error("Member not in group"));
        }

        self.blank_path(removed);
        self.truncate();
        Ok(())
    }

    pub fn root_hash(&self) -> Result<TreeHash<C>> {
        stack::update();
        self.hash(self.size().root()).map(|h| TreeHash(h))
    }

    fn hash(&self, index: NodeIndex) -> Result<HashOutput<C>> {
        stack::update();
        if index.is_leaf() {
            self.leaf_hash(index)
        } else {
            self.parent_hash(index)
        }
    }

    fn leaf_hash(&self, index: NodeIndex) -> Result<HashOutput<C>> {
        stack::update();
        // struct {
        //     uint32 leaf_index;
        //     optional<LeafNode> leaf_node;
        // } LeafNodeHashInput;
        let mut h = C::Hash::default();

        let leaf_index = LeafIndex::try_from(index)?;
        leaf_index.serialize(&mut h)?;

        let optional_leaf = self.leaf_node_at(leaf_index);
        optional_leaf.serialize(&mut h)?;

        Ok(h.finalize())
    }

    fn parent_hash(&self, index: NodeIndex) -> Result<HashOutput<C>> {
        stack::update();
        // struct {
        //     optional<ParentNode> parent_node;
        //     opaque left_hash<V>;
        //     opaque right_hash<V>;
        // } ParentNodeHashInput;
        let mut h = C::Hash::default();

        let optional_parent = self.parent_node_at(index.try_into()?);
        optional_parent.serialize(&mut h)?;

        self.hash(index.left().unwrap())?.serialize(&mut h)?;
        self.hash(index.right().unwrap())?.serialize(&mut h)?;

        Ok(h.finalize())
    }

    fn expand(&mut self) -> Result<()> {
        stack::update();
        let leaf_width = if self.leaf_nodes.is_empty() {
            1
        } else {
            2 * self.leaf_nodes.len()
        };
        let parent_width = leaf_width - 1;
        self.leaf_nodes
            .resize_default(leaf_width)
            .map_err(|()| Error("Resize error"))?;
        self.parent_nodes
            .resize_default(parent_width)
            .map_err(|()| Error("Resize error"))
    }

    fn truncate(&mut self) {
        let mut start = self.leaf_nodes.len() / 2;
        let mut end = self.leaf_nodes.len();
        while start > 0
            && self.leaf_nodes[start..end]
                .iter()
                .all(core::option::Option::is_none)
        {
            end = start;
            start /= 2;
        }

        let leaf_width = end;
        let parent_width = leaf_width - 1;
        self.leaf_nodes.resize_default(leaf_width).unwrap();
        self.parent_nodes.resize_default(parent_width).unwrap();
    }

    fn blank_path(&mut self, leaf_index: LeafIndex) {
        let node_index: NodeIndex = leaf_index.into();

        *self.leaf_node_at_mut(leaf_index) = None;

        let mut p = node_index.parent(self.size().into());
        while let Some(index) = p {
            *self.parent_node_at_mut(index.try_into().unwrap()) = None;
            p = index.parent(self.size().into());
        }
    }

    pub fn update_direct_path(
        &mut self,
        rng: &mut impl CryptoRng,
        from: LeafIndex,
        signature_priv: &SignaturePrivateKey<C>,
    ) -> Result<(RatchetTreePriv<C>, UpdatePath<C>)>
    where
        C: DependentSizes,
    {
        let path = self.resolve_path(from);

        // Generate path secrets
        let mut path_secret = HashOutput::<C>::random(rng);
        let path_secrets: Vec<_, { consts::MAX_TREE_DEPTH }> = path
            .iter()
            .map(|(_n, res)| {
                if res.is_empty() {
                    None
                } else {
                    path_secret = C::derive_secret(&path_secret, b"path");
                    Some(PathSecret(path_secret.clone()))
                }
            })
            .collect();

        let commit_secret = C::derive_secret(&path_secret, b"path");

        // Compute the corresponding public keys
        let nodes: Result<Vec<_, { consts::MAX_TREE_DEPTH }>> = path_secrets
            .iter()
            .filter_map(|ps| ps.as_ref())
            .map(|ps| {
                let node_secret = C::derive_secret(&ps.0, b"node");
                let (_, encryption_key) = C::hpke_derive(&node_secret)?;
                Ok(UpdatePathNode {
                    encryption_key,
                    encrypted_path_secret: Vec::default(),
                })
            })
            .collect();
        let nodes = nodes?;

        // Assemble and merge the update path
        let parent_hash = self.merge(&nodes, from)?;

        // Re-sign the leaf node
        let Some(leaf_node) = self.leaf_node_at_mut(from).as_mut() else {
            return Err(Error("Encap from blank leaf"));
        };

        let (encryption_priv, encryption_key) = C::hpke_generate(rng)?;
        leaf_node.tbs.encryption_key = encryption_key;
        leaf_node.tbs.leaf_node_source = LeafNodeSource::Commit(parent_hash);
        leaf_node.re_sign(signature_priv)?;

        // Assemble the return values
        let ratchet_tree_priv = RatchetTreePriv {
            encryption_priv,
            path_secrets,
            commit_secret,
        };

        let update_path = UpdatePath {
            leaf_node: leaf_node.clone(),
            nodes,
        };

        Ok((ratchet_tree_priv, update_path))
    }

    pub fn merge_leaf(&mut self, from: LeafIndex, leaf_node: LeafNode<C>) {
        self.leaf_node_at_mut(from).replace(leaf_node);
    }

    pub fn encrypt_path_secrets(
        &self,
        rng: &mut impl CryptoRng,
        from: LeafIndex,
        group_context: &GroupContext<C>,
        ratchet_tree_priv: &RatchetTreePriv<C>,
        mut update_path: UpdatePath<C>,
    ) -> Result<UpdatePath<C>>
    where
        C: DependentSizes,
    {
        let path = self.resolve_path(from);
        let group_context = group_context.materialize()?;

        let filtered_priv = ratchet_tree_priv
            .path_secrets
            .iter()
            .filter_map(|ps| ps.as_ref());
        let resolutions = path
            .iter()
            .map(|(_, res)| res)
            .filter(|res| !res.is_empty());
        let encrypted_path_secret = update_path
            .nodes
            .iter_mut()
            .map(|n| &mut n.encrypted_path_secret);
        for ((ps, res), enc) in filtered_priv.zip(resolutions).zip(encrypted_path_secret) {
            let raw_hash_output = RawHashOutput::<C>::try_from(ps.0.as_ref())
                .map_err(|_| Error("This shouldn't have failed"))?;
            let raw_path_secret = RawPathSecret(raw_hash_output);
            for n in res {
                let encryption_key = self.encryption_key_at(*n).unwrap();
                let encrypted_path_secret =
                    raw_path_secret.hpke_seal(rng, encryption_key, &group_context)?;

                enc.push(encrypted_path_secret).unwrap();
            }
        }

        Ok(update_path)
    }

    pub fn select_path_secret(
        &self,
        ratchet_tree_priv: &RatchetTreePriv<C>,
        from: LeafIndex,
        to: LeafIndex,
    ) -> Result<PathSecret<C>> {
        stack::update();
        let path = self.resolve_path(from);
        let parent_index = path.iter().position(|(n, _)| n.is_above_or_eq(to)).unwrap();
        ratchet_tree_priv.path_secrets[parent_index]
            .clone()
            .ok_or(Error("Missing path secret"))
    }

    pub fn decap(
        &mut self,
        ratchet_tree_priv: &mut RatchetTreePriv<C>,
        update_path: &UpdatePath<C>,
        from: LeafIndex,
        to: LeafIndex,
        group_context: &GroupContext<C>,
    ) -> Result<()>
    where
        C: DependentSizes,
    {
        let path = self.resolve_path(from);
        let group_context = group_context.materialize()?;

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

        let res = &path[path_index].1;
        let to_node = NodeIndex::from(to);
        let res_index = if res.contains(&to_node) {
            // Unmerged leaf
            res.iter().position(|n| *n == to_node).unwrap()
        } else {
            // Find a parent node
            res.iter().position(|n| n.is_above_or_eq(to)).unwrap()
        };

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
                let ps = ps.as_ref().unwrap();
                let decrypt_node_secret = C::derive_secret(&ps.0, b"node");
                let (encryption_priv, _encryption_key) = C::hpke_derive(&decrypt_node_secret)?;

                Ok(encryption_priv)
            })
            .transpose()?;

        let encryption_priv = if let Some(encryption_priv) = path_encryption_priv.as_ref() {
            encryption_priv
        } else {
            &ratchet_tree_priv.encryption_priv
        };

        // Decrypt the path secret
        let encrypted_path_secret =
            update_path.nodes[update_path_index].encrypted_path_secret[res_index].clone();
        let raw_path_secret =
            RawPathSecret::hpke_open(encrypted_path_secret, encryption_priv, &group_context)?;
        let mut path_secret: HashOutput<C> = raw_path_secret
            .0
            .as_ref()
            .try_into()
            .map_err(|_| Error("This should not have failed"))?;

        // Grow / shrink the path to accommodate changes in the size of the tree
        ratchet_tree_priv
            .path_secrets
            .resize_default(path.len())
            .unwrap();

        // Implant the path secret and hash to the end
        ratchet_tree_priv.path_secrets[path_index] = Some(PathSecret(path_secret.clone()));
        let start = path_index + 1;
        let end = ratchet_tree_priv.path_secrets.len();
        for i in start..end {
            if path[i].1.is_empty() {
                ratchet_tree_priv.path_secrets[i] = None;
                continue;
            }

            path_secret = C::derive_secret(&path_secret, b"path");
            ratchet_tree_priv.path_secrets[i] = Some(PathSecret(path_secret.clone()));
        }

        ratchet_tree_priv.commit_secret = C::derive_secret(&path_secret, b"path");

        Ok(())
    }

    fn parent_hash_now(
        &mut self,
        last_parent: Option<NodeIndex>,
        from: LeafIndex,
    ) -> Result<HashOutput<C>> {
        stack::update();
        let Some(p) = last_parent else {
            // Parent hash of the root is an empty byte string
            return Ok(HashOutput::<C>::default());
        };

        let Some(parent) = self.parent_node_at(p.try_into()?) else {
            unreachable!();
        };

        let copath_child = p.copath_child(from).unwrap();
        let original_sibling_tree_hash = self.hash(copath_child)?;

        // struct {
        //     HPKEPublicKey encryption_key;
        //     opaque parent_hash<V>;
        //     opaque original_sibling_tree_hash<V>;
        // } ParentHashInput;
        let mut h = C::Hash::default();
        parent.public_key.serialize(&mut h)?;
        parent.parent_hash.serialize(&mut h)?;
        original_sibling_tree_hash.serialize(&mut h)?;
        Ok(h.finalize())
    }

    pub fn merge(&mut self, nodes: &[UpdatePathNode<C>], from: LeafIndex) -> Result<HashOutput<C>>
    where
        C: DependentSizes,
    {
        let path = self.resolve_path(from);
        let filtered_path = path
            .iter()
            .filter(|(_, res)| !res.is_empty())
            .map(|(n, _)| *n);

        let keys = nodes.iter().map(|n| n.encryption_key.clone());
        let index_key_pairs: Vec<_, { consts::MAX_TREE_DEPTH }> = filtered_path.zip(keys).collect();
        let mut last_parent: Option<NodeIndex> = None;
        for (n, public_key) in index_key_pairs.iter().rev() {
            let parent_hash = self.parent_hash_now(last_parent, from)?;
            last_parent.replace(*n);

            *self.parent_node_at_mut(ParentIndex::try_from(*n).unwrap()) = Some(ParentNode {
                public_key: public_key.clone(),
                parent_hash,
                unmerged_leaves: Vec::default(),
            });
        }

        self.parent_hash_now(last_parent, from)
    }

    fn original_tree_hash(
        &self,
        cache: &mut TreeHashCache<C>,
        index: NodeIndex,
        parent_except: &[LeafIndex],
    ) -> Result<HashOutput<C>> {
        stack::update();
        // Scope the unmerged leaves list down to this subtree
        let local_except: Vec<_, { consts::MAX_RESOLUTION_SIZE }> = parent_except
            .iter()
            .filter(|&&n| index.is_above_or_eq(n))
            .copied()
            .collect();

        if local_except.is_empty() {
            return self.hash(index);
        }

        // If this method has been called before with the same number of excluded
        // leaves (which implies the same set), then use the cached value.
        if let Some(hash) = cache.get(&(index, local_except.len())) {
            return Ok(hash.clone());
        }

        // If there is no entry in either cache, recompute the value
        let hash = if let Ok(leaf_index) = LeafIndex::try_from(index) {
            // A leaf node with local changes is by definition excluded from the parent
            // hash.  So we return the hash of an empty leaf.
            let none: Option<Nil> = None;

            let mut h = C::Hash::default();
            leaf_index.serialize(&mut h)?;
            none.serialize(&mut h)?;
            h.finalize()
        } else {
            // If there is no cached value, recalculate the child hashes with the
            // specified `except` list, removing the `except` list from
            // `unmerged_leaves`.
            let left_hash = self.original_tree_hash(cache, index.left().unwrap(), &local_except)?;
            let right_hash =
                self.original_tree_hash(cache, index.right().unwrap(), &local_except)?;

            let parent_node = self.parent_node_at(index.try_into()?).map(|parent| {
                let mut parent = parent.clone();
                parent.unmerged_leaves.retain(|i| !local_except.contains(i));
                parent
            });

            let mut h = C::Hash::default();
            parent_node.serialize(&mut h)?;
            left_hash.serialize(&mut h)?;
            right_hash.serialize(&mut h)?;
            h.finalize()
        };

        cache
            .insert((index, local_except.len()), hash.clone())
            .unwrap();
        Ok(hash)
    }

    fn original_parent_hash(
        &self,
        cache: &mut TreeHashCache<C>,
        parent: NodeIndex,
        sibling: NodeIndex,
    ) -> Result<HashOutput<C>> {
        stack::update();
        let parent_index = ParentIndex::try_from(parent).unwrap();
        let Some(parent_node) = self.parent_node_at(parent_index) else {
            unreachable!();
        };

        let sibling_hash = self.original_tree_hash(cache, sibling, &parent_node.unmerged_leaves)?;

        let mut h = C::Hash::default();
        parent_node.public_key.serialize(&mut h)?;
        parent_node.parent_hash.serialize(&mut h)?;
        sibling_hash.serialize(&mut h)?;
        Ok(h.finalize())
    }

    fn has_parent_hash(&self, node: NodeIndex, target_hash: &HashOutput<C>) -> bool {
        stack::update();
        self.resolve(node)
            .iter()
            .filter_map(|&n| self.parent_hash_at(n))
            .any(|parent_hash| parent_hash == *target_hash)
    }

    pub fn parent_hash_valid(&self) -> Result<bool> {
        stack::update();
        let mut cache = TreeHashCache::<C>::new();

        let width: NodeCount = self.size().into();
        let height = width.root().level();
        for level in 1..height {
            let stride = 2 << level;
            let start = (stride >> 1) - 1;

            for p in (start..width.0).step_by(stride) {
                let p = NodeIndex(p); // TODO simplify
                if self
                    .parent_node_at(ParentIndex::try_from(p).unwrap())
                    .is_none()
                {
                    continue;
                }

                let l = p.left().unwrap();
                let r = p.right().unwrap();

                let lh = self.original_parent_hash(&mut cache, p, r)?;
                let rh = self.original_parent_hash(&mut cache, p, l)?;

                if !self.has_parent_hash(l, &lh) && !self.has_parent_hash(r, &rh) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    fn resolve_path(&self, leaf_node: LeafIndex) -> ResolutionPath {
        stack::update();
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
        stack::update();
        let mut res = Vec::new();

        if let Ok(n) = LeafIndex::try_from(subtree_root) {
            if self.leaf_node_at(n).is_some() {
                // The resolution of a non-blank leaf node comprises the node itself.
                res.push(subtree_root).unwrap();
            } else {
                // The resolution of a blank leaf node is the empty list.
            }
        } else {
            let n = ParentIndex::try_from(subtree_root).unwrap();
            if let Some(node) = self.parent_node_at(n) {
                // The resolution of a non-blank parent node comprises the node itself, followed by
                // its unmerged leaves.
                res.push(subtree_root).unwrap();
                res.extend(node.unmerged_leaves.iter().map(|&i| i.into()));
            } else {
                // The resolution of a blank intermediate node is the result of concatenating the
                // resolution of its left child with the resolution of its right child, in that
                // order.
                let left = subtree_root.left().unwrap();
                res.extend_from_slice(&self.resolve(left)).unwrap();

                let right = subtree_root.right().unwrap();
                res.extend_from_slice(&self.resolve(right)).unwrap();
            }
        }

        res
    }
}
