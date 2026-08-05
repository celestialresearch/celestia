// Copyright © 2026 @sudocelestia. All rights reserved.
//
// PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
//
// No licence, permission or authorisation is granted to use, copy, modify,
// compile, execute, distribute, publish, sublicense or otherwise exploit this
// file, except to the limited extent unavoidably permitted by applicable law
// or GitHub's Terms of Service.
//
// See the LICENSE file at the repository root for the complete terms.

package linuxamd64feasibility

const (
	observationSchema   = "celestia.linux-amd64-feasibility-observation.v1"
	maxObservationBytes = 1 << 20
	primitiveCount      = 16
	memberCount         = 4
)

type observation struct {
	SchemaVersion string                               `json:"schema_version"`
	Status        string                               `json:"status"`
	Reason        string                               `json:"reason"`
	ProductCommit string                               `json:"product_commit"`
	ProbeCommit   string                               `json:"probe_commit"`
	ProbeSHA256   string                               `json:"probe_sha256"`
	Host          hostObservation                      `json:"host"`
	Primitives    [primitiveCount]primitiveObservation `json:"primitives"`
	Evidence      *observationEvidence                 `json:"evidence"`
	Cleanup       cleanupObservation                   `json:"cleanup"`
}

type hostObservation struct {
	OperatingSystem string `json:"operating_system"`
	Architecture    string `json:"architecture"`
	KernelRelease   string `json:"kernel_release"`
	BootID          string `json:"boot_id"`
}

type observationEvidence struct {
	Cgroup     *cgroupObservation    `json:"cgroup"`
	Evidence   *evidenceRoot         `json:"evidence_root"`
	Namespaces *namespaceObservation `json:"namespaces"`
	Fixture    *fixtureObservation   `json:"fixture"`
}

type cgroupObservation struct {
	MountDevice   uint64 `json:"mount_device"`
	MountInode    uint64 `json:"mount_inode"`
	SubtreeDevice uint64 `json:"subtree_device"`
	SubtreeInode  uint64 `json:"subtree_inode"`
}

type evidenceRoot struct {
	Filesystem string `json:"filesystem"`
	Device     uint64 `json:"device"`
}

type namespaceObservation struct {
	User             bool                `json:"user"`
	PID              bool                `json:"pid"`
	IPC              bool                `json:"ipc"`
	UTS              bool                `json:"uts"`
	Mount            bool                `json:"mount"`
	Network          bool                `json:"network"`
	PrivateProc      bool                `json:"private_proc"`
	LoopbackDisabled bool                `json:"loopback_disabled"`
	MountPropagation string              `json:"mount_propagation"`
	UIDMap           [1]idMapObservation `json:"uid_map"`
	GIDMap           [1]idMapObservation `json:"gid_map"`
	Descriptors      [3]int              `json:"descriptors"`
}

type idMapObservation struct {
	Inside  uint32 `json:"inside"`
	Outside uint32 `json:"outside"`
	Length  uint32 `json:"length"`
}

type fixtureObservation struct {
	SHA256     string `json:"sha256"`
	ELFMachine string `json:"elf_machine"`
	ELFType    string `json:"elf_type"`
	PTInterp   bool   `json:"pt_interp"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
}

type primitiveObservation struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
}

type cleanupObservation struct {
	Attempted   bool                           `json:"attempted"`
	Complete    bool                           `json:"complete"`
	CgroupEmpty bool                           `json:"cgroup_empty"`
	Members     [memberCount]memberObservation `json:"members"`
}

type memberObservation struct {
	Role   string `json:"role"`
	PID    uint32 `json:"pid"`
	Exited bool   `json:"exited"`
}
