pub fn level(index: usize) -> usize {
    if index & 0b1 == 0 {
        0
    } else {
        index.trailing_ones() as usize
    }
}

pub fn root(w: usize) -> usize {
    w / 2
}

pub fn parent(index: usize, width: usize) -> Option<usize> {
    if index == root(width) {
        None
    } else {
        let k = level(index);
        let b = (index >> (k + 1)) & 0x01;
        Some((index | (1 << k)) ^ (b << (k + 1)))
    }
}

pub fn left(index: usize) -> Option<usize> {
    let k = level(index);
    (k != 0).then_some(index ^ (0b01 << (k - 1)))
}

pub fn right(index: usize) -> Option<usize> {
    let k = level(index);
    (k != 0).then_some(index ^ (0b11 << (k - 1)))
}

pub fn step_towards(parent: usize, leaf: usize) -> Option<usize> {
    let k = level(parent);

    // If parent is a leaf or leaf is not below parent
    if k == 0 || (parent >> (k + 1)) != (leaf >> (k + 1)) {
        return None;
    }

    let mask = 1 << k;
    let clear = 0b1 << (k - 1);
    Some((parent & !mask) ^ clear ^ (leaf & mask))
}
