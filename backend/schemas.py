from pydantic import BaseModel, Field


class FailedLoginEvent(BaseModel):
    timestamp: str | None = Field(default=None, description="Timestamp parsed from auth.log if present.")
    ip_address: str = Field(description="Source IP address for the failed SSH login attempt.")
    username: str | None = Field(default=None, description="Attempted SSH username.")
    method: str | None = Field(default=None, description="Authentication method, such as password.")
    line_number: int = Field(description="Original line number from the uploaded log.")
    raw_line: str = Field(description="Original auth.log line for traceability.")


class TopIP(BaseModel):
    ip_address: str = Field(description="Source IP address found in the log file.")
    attempts: int = Field(description="Number of failed login attempts from this IP.")
    is_suspicious: bool = Field(description="True when the IP matches a simple detection rule.")


class TargetedUsername(BaseModel):
    username: str = Field(description="Username found in failed SSH login attempts.")
    attempts: int = Field(description="How many times this username was targeted.")


class AnalysisStatistics(BaseModel):
    top_ips: list[TopIP] = Field(default_factory=list, description="Top source IPs ordered by frequency.")
    most_targeted_usernames: list[TargetedUsername] = Field(
        default_factory=list,
        description="Usernames most frequently targeted by failed SSH login attempts.",
    )
    suspicious_ips: list[str] = Field(
        default_factory=list,
        description="IPs that crossed a simple brute-force or username enumeration threshold.",
    )


class SecurityAlert(BaseModel):
    severity: str = Field(description="Alert severity such as info, medium, or high.")
    alert_type: str = Field(description="Detection category, for example brute_force.")
    ip_address: str | None = Field(default=None, description="Related source IP if applicable.")
    message: str = Field(description="Human-readable explanation of the detection result.")


class AnalyzeResponse(BaseModel):
    total_failed_logins: int = Field(description="Total number of failed SSH login attempts found.")
    top_ips: list[TopIP] = Field(default_factory=list, description="Top source IPs ordered by frequency.")
    events: list[FailedLoginEvent] = Field(default_factory=list, description="Detailed failed SSH login events.")
    statistics: AnalysisStatistics = Field(description="Summary statistics derived from the parsed events.")
    alerts: list[SecurityAlert] = Field(default_factory=list, description="Human-readable security findings.")
