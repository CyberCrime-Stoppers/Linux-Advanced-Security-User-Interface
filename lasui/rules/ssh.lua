-- rules/ssh.lua: SSH daemon hardening checks
return {
  name = "sshd_hardening",
  version = "1.0",
  check = function(ctx)
    local c = ctx:read_file("/etc/ssh/sshd_config")
    local issues = {}
    if not c:match("PermitRootLogin%s+no") then
      table.insert(issues, { severity = "high",
        msg = "PermitRootLogin is not disabled" })
    end
    return issues
  end,
}
