use crate::common::{Error, Result};
use crate::protocol::LeafIndex;
use crate::stack;

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Hash)]
pub struct NodeIndex(pub usize);

impl From<LeafIndex> for NodeIndex {
    fn from(i: LeafIndex) -> Self {
        stack::update();
        Self((2 * i.0) as usize)
    }
}

impl TryFrom<NodeIndex> for LeafIndex {
    type Error = Error;

    fn try_from(i: NodeIndex) -> Result<Self> {
        stack::update();
        if i.is_leaf() {
            Ok(Self((i.0 as u32) / 2))
        } else {
            Err(Error("Node index is not a leaf"))
        }
    }
}

impl NodeIndex {
    #[must_use]
    pub fn level(self) -> usize {
        stack::update();
        self.0.trailing_ones() as usize
    }

    #[must_use]
    pub fn is_leaf(self) -> bool {
        stack::update();
        self.level() == 0
    }

    #[must_use]
    pub fn parent(self, width: NodeCount) -> Option<Self> {
        stack::update();
        if self == width.root() {
            None
        } else {
            let k = self.level();
            let b = (self.0 >> (k + 1)) & 0x01;
            Some(Self((self.0 | (1 << k)) ^ (b << (k + 1))))
        }
    }

    #[must_use]
    pub fn left(self) -> Option<Self> {
        stack::update();
        let k = self.level();
        (k != 0).then_some(Self(self.0 ^ (0b01 << (k - 1))))
    }

    #[must_use]
    pub fn right(self) -> Option<Self> {
        stack::update();
        let k = self.level();
        (k != 0).then_some(Self(self.0 ^ (0b11 << (k - 1))))
    }

    // This function will return an out-of-bounds index if applied to the root.
    fn sibling_unchecked(self) -> Self {
        stack::update();
        let k = self.level();
        Self(self.0 ^ (0b10 << k))
    }

    #[must_use]
    pub fn dirpath_child(self, leaf: LeafIndex) -> Option<Self> {
        stack::update();
        let leaf = NodeIndex::from(leaf);
        let k = self.level();

        // If parent is a leaf or leaf is not below parent
        if k == 0 || (self.0 >> (k + 1)) != (leaf.0 >> (k + 1)) {
            return None;
        }

        let mask = 1 << k;
        let clear = 0b1 << (k - 1);
        Some(Self((self.0 & !mask) ^ clear ^ (leaf.0 & mask)))
    }

    #[must_use]
    pub fn copath_child(self, leaf: LeafIndex) -> Option<Self> {
        stack::update();
        self.dirpath_child(leaf).map(NodeIndex::sibling_unchecked)
    }

    #[must_use]
    pub fn is_above_or_eq(self, leaf: LeafIndex) -> bool {
        stack::update();
        let leaf = NodeIndex::from(leaf);
        let k = self.level();
        k >= leaf.level() && (self.0 >> (k + 1)) == (leaf.0 >> (k + 1))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub struct LeafCount(pub usize);

impl From<NodeCount> for LeafCount {
    fn from(n: NodeCount) -> Self {
        stack::update();
        if n.0 == 0 {
            Self(0)
        } else {
            Self(n.0 / 2 + 1)
        }
    }
}

impl LeafCount {
    #[must_use]
    pub fn root(&self) -> NodeIndex {
        stack::update();
        NodeCount::from(*self).root()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub struct NodeCount(pub usize);

impl From<LeafCount> for NodeCount {
    fn from(n: LeafCount) -> Self {
        stack::update();
        if n.0 == 0 {
            Self(0)
        } else {
            Self(2 * n.0 - 1)
        }
    }
}

impl NodeCount {
    #[must_use]
    pub fn root(&self) -> NodeIndex {
        stack::update();
        NodeIndex(self.0 / 2)
    }
}
