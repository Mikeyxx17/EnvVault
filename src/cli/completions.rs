//! Static shell completions. They never list Secret names.

use super::args::CompletionShell;

pub(super) fn render(shell: CompletionShell) -> &'static str {
    match shell {
        CompletionShell::Bash => BASH,
        CompletionShell::Zsh => ZSH,
        CompletionShell::Powershell => POWERSHELL,
    }
}

const BASH: &str = r#"_envvault() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  local cmds="init set verify list exists remove rename change-password import example identity profile policy audit keystore session run completions uninstall"
  case "${prev}" in
    identity) COMPREPLY=($(compgen -W "register list revoke rotate" -- "${cur}")); return ;;
    profile) COMPREPLY=($(compgen -W "create" -- "${cur}")); return ;;
    policy) COMPREPLY=($(compgen -W "list grant-use grant-inspect revoke-use" -- "${cur}")); return ;;
    audit) COMPREPLY=($(compgen -W "list migrate-v2 serve-anchor configure-anchor anchor-status" -- "${cur}")); return ;;
    keystore) COMPREPLY=($(compgen -W "enable status rotate disable" -- "${cur}")); return ;;
    session) COMPREPLY=($(compgen -W "whoami" -- "${cur}")); return ;;
    completions) COMPREPLY=($(compgen -W "bash zsh powershell" -- "${cur}")); return ;;
  esac
  COMPREPLY=($(compgen -W "${cmds} --vault --as --format --masked-input --help --version" -- "${cur}"))
}
complete -F _envvault envvault
"#;

const ZSH: &str = r"#compdef envvault
_envvault() {
  local -a commands
  commands=(
    'init:Initialize a Vault'
    'set:Create or replace a Secret'
    'verify:Compare a Secret without revealing it'
    'list:List authorized Secret names'
    'exists:Check whether a Secret exists'
    'remove:Delete a Secret'
    'rename:Rename a Secret'
    'change-password:Replace the Master Password'
    'import:Import a dotenv file'
    'example:Write a value-free dotenv example'
    'identity:Manage application and agent identities'
    'profile:Create runtime Profiles'
    'policy:Inspect and update authorization'
    'audit:Inspect Audit history'
    'keystore:Manage machine unlock'
    'session:Inspect a machine identity'
    'run:Inject Secrets into a process'
    'completions:Print shell completions'
    'uninstall:Remove the installed binary'
  )
  _describe -t commands 'envvault command' commands
}
compdef _envvault envvault
";

const POWERSHELL: &str = r#"Register-ArgumentCompleter -Native -CommandName envvault -ScriptBlock {
  param($wordToComplete)
  $cmds = @(
    'init','set','verify','list','exists','remove','rename','change-password','import','example',
    'identity','profile','policy','audit','keystore','session','run','completions','uninstall'
  )
  $cmds | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
"#;
