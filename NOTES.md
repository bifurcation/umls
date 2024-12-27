

(SignatureKey, Credential) -> (KeyPackagePriv, KeyPackage)

(KeyPackagePrivView, KeyPackageView) -> (GroupState, RatchetTree)

(KeyPackagePrivView, KeyPackageView, WelcomeView) -> (GroupState, RatchetTree)

(GroupStateView, RatchetTreeView, KeyPackageView) -> (GroupState, RatchetTree, Commit, Welcome)

(GroupStateView, RatchetTreeView, LeafIndex) -> (GroupState, RatchetTree, Commit)

(GroupStateView, RatchetTreeView, CommitView) -> (GroupState, RatchetTree)





Commit
CommitView

Credential

GroupState
GroupStateView

KeyPackage
KeyPackagePriv

KeyPackagePrivView
KeyPackageView

LeafIndex

RatchetTree
RatchetTreeView

SignatureKey

Welcome
WelcomeView
