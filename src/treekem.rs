use crate::common::*;
use crate::crypto::*;
use crate::io::*;
use crate::protocol::*;
use crate::syntax::*;
use crate::tree_math::*;
use crate::{mls_enum, mls_struct, mls_struct_serialize};

use heapless::Vec;

mod consts {
    pub use crate::protocol::consts::MAX_GROUP_SIZE;

    pub const MAX_NODE_WIDTH: usize = 2 * MAX_GROUP_SIZE - 1;
    pub const ROOT_NODE_INDEX: usize = MAX_GROUP_SIZE - 1;
}

type UnmergedLeavesList = Vec<LeafIndex, { consts::MAX_GROUP_SIZE }>;
type UnmergedLeavesListView<'a> = Vec<LeafIndexView<'a>, { consts::MAX_GROUP_SIZE }>;

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

type OptionalNode = Option<Node>;
type OptionalNodeView<'a> = Option<NodeView<'a>>;

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

    pub fn add_leaf(&mut self, leaf_node: LeafNode) -> Result<()> {
        // Assign to a blank leaf node if one exists
        let blank = self
            .nodes
            .iter()
            .step_by(2)
            .position(|n| n.is_none())
            .map(|i| LeafIndex(i as u32));
        if let Some(index) = blank {
            self.blank_path(index);
            *self.node_at_mut(index.into()) = Some(Node::Leaf(leaf_node));
            return Ok(());
        }

        let next_leaf = if self.nodes.is_empty() {
            0
        } else {
            self.nodes.len() + 1
        };

        self.expand()?;
        self.nodes[next_leaf] = Some(Node::Leaf(leaf_node));
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

    fn blank_path(&mut self, leaf_index: LeafIndex) {
        let node_index: NodeIndex = leaf_index.into();
        *self.node_at_mut(node_index) = None;
        let mut p = node_index.parent(self.size().into());
        while let Some(index) = p {
            *self.node_at_mut(index) = None;
            p = index.parent(self.size().into());
        }
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
}
