use serde::Deserialize;
use serde::Serialize;

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CarefulResumePhaseUpdated {
    pub old: Option<CarefulResumePhase>,
    pub new: CarefulResumePhase,
    pub state_data: CarefulResumeStateParameters,
    pub restored_data: Option<CarefulResumeRestoredParameters>,
    pub trigger: Option<CarefulResumeTrigger>
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CarefulResumeTrigger {
    PacketLoss, // Loss triggers moving to safe retreat
    CwndLimited, // Trigger for moving to unvalidated
    CrMarkAcknowledged, // Trigger for moving to validating or normal
    RttNotValidated, // Trigger for moving to normal, when CR not allowed
    EcnCe, // Trigger for moving to safe retreat.
    ExitRecovery, // Trigger for moving to normal 1rtt after a congestion event
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CarefulResumePhase {
    Reconnaissance,
    Unvalidated,
    Validating,
    Normal,
    SafeRetreat,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct CarefulResumeStateParameters {
    pub pipesize: u64,
    pub cr_mark: u64,
    pub cwnd: Option<u64>,
    pub ssthresh: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug)]
pub struct CarefulResumeRestoredParameters {
    pub previous_cwnd: u64,
    pub previous_rtt: f32,
}