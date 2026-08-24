package cli

// Exported constructors for the app entrypoint.

func NewInitCmd(env *Env) Command        { return newInitCmd(env) }
func NewDoctorCmd(env *Env) Command      { return newDoctorCmd(env) }
func NewValidateCmd(env *Env) Command    { return newValidateCmd(env) }
func NewHealthcheckCmd(env *Env) Command { return newHealthcheckCmd(env) }
func NewRunCmd(env *Env) Command         { return newRunCmd(env) }
func NewInspectCmd(env *Env) Command     { return newInspectCmd(env) }
func NewRecommendCmd(env *Env) Command   { return newRecommendCmd(env) }
func NewMigrateCmd(env *Env) Command     { return newMigrateCmd(env) }
func NewRulesCmd(env *Env) Command       { return newRulesCmd(env) }
func NewExtCmd(env *Env) Command         { return newExtCmd(env) }
func NewVersionCmd(env *Env) Command     { return newVersionCmd(env) }
func NewCompletionCmd(env *Env) Command  { return newCompletionCmd(env) }
