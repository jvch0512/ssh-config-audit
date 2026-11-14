defmodule SshConfigAuditTest do
  use ExUnit.Case, async: true
  import SshConfigAudit

  defp rules(text), do: text |> audit() |> Enum.map(& &1.rule) |> Enum.uniq()
  @clean "PermitRootLogin no\nPasswordAuthentication no\nAllowGroups ssh\n"

  test "a hardened config has no findings" do
    assert audit(@clean) == []
    assert score([]) == 100
  end

  test "root login" do
    assert "SSH001" in rules("PermitRootLogin yes\n" <> @clean)
    refute "SSH001" in rules("PermitRootLogin prohibit-password\nPasswordAuthentication no\nAllowGroups ssh\n")
  end

  test "keywords are case-insensitive and = is accepted" do
    assert "SSH001" in rules("permitrootlogin YES\nPasswordAuthentication no\nAllowGroups ssh\n")
    assert "SSH001" in rules("PermitRootLogin=yes\nPasswordAuthentication no\nAllowGroups ssh\n")
  end

  test "the FIRST value wins, like OpenSSH" do
    assert rules("PermitRootLogin no\nPermitRootLogin yes\nPasswordAuthentication no\nAllowGroups ssh\n") == []
    assert "SSH001" in rules("PermitRootLogin yes\nPermitRootLogin no\nPasswordAuthentication no\nAllowGroups ssh\n")
  end

  test "comments and inline comments are ignored" do
    assert rules("# PermitRootLogin yes\nPermitRootLogin no # yes\nPasswordAuthentication no\nAllowGroups ssh\n") == []
  end

  test "Match blocks are not evaluated" do
    text = @clean <> "Match User backup\n  PermitRootLogin yes\n  PasswordAuthentication yes\n"
    assert audit(text) == []
  end

  test "an unset PasswordAuthentication is reported because the default is yes" do
    f = Enum.find(audit("PermitRootLogin no\nAllowGroups ssh\n"), &(&1.rule == "SSH002"))
    assert f && f.line == nil
  end

  test "empty passwords and protocol 1" do
    assert "SSH003" in rules("PermitEmptyPasswords yes\n" <> @clean)
    assert "SSH004" in rules("Protocol 1\n" <> @clean)
    refute "SSH004" in rules("Protocol 2\n" <> @clean)
  end

  test "weak crypto is listed by name" do
    [f] = audit("Ciphers aes256-gcm@openssh.com,3des-cbc\n" <> @clean)
    assert f.rule == "SSH005" and f.message =~ "3des-cbc" and f.message =~ "cipher"
    assert "SSH005" in rules("MACs hmac-md5\n" <> @clean)
    assert "SSH005" in rules("KexAlgorithms diffie-hellman-group1-sha1\n" <> @clean)
    assert audit("Ciphers +aes256-gcm@openssh.com\n" <> @clean) == []
  end

  test "MaxAuthTries only flags values above 4 and survives junk" do
    assert "SSH007" in rules("MaxAuthTries 6\n" <> @clean)
    refute "SSH007" in rules("MaxAuthTries 4\n" <> @clean)
    refute "SSH007" in rules("MaxAuthTries lots\n" <> @clean)
  end

  test "missing allow list is reported" do
    assert "SSH011" in rules("PermitRootLogin no\nPasswordAuthentication no\n")
    refute "SSH011" in rules("AllowUsers deploy\n" <> "PermitRootLogin no\nPasswordAuthentication no\n")
  end

  test "findings are sorted by severity and the score drops" do
    fs = audit("PermitRootLogin yes\nX11Forwarding yes\nPasswordAuthentication no\nAllowGroups ssh\n")
    assert hd(fs).severity == :critical
    assert score(fs) == 65 and grade(score(fs)) == "C"
    assert grade(0) == "F" and grade(95) == "A"
  end

  test "garbage and empty input do not crash" do
    assert is_list(audit(""))
    assert is_list(audit("\0\0\n= = =\nMatch\n" <> String.duplicate("x", 5000)))
    assert is_list(audit(<<255, 254, 10, 0, 1>>))
  end

  test "html escapes and has a strict CSP" do
    f = %SshConfigAudit.Finding{rule: "SSH001", severity: :high, message: "<script>alert(1)</script>", line: 1, fix: "<b>"}
    html = render_html([f], "<img src=x>")
    refute html =~ "<script>alert"
    assert html =~ "&lt;script&gt;"
    refute html =~ "<img src=x>"
    assert html =~ "default-src 'none'"
  end

  test "sample configs" do
    legacy = File.read!("examples/sshd_config_legacy") |> audit()
    assert length(legacy) == 11
    assert hd(legacy).severity == :critical
    assert score(legacy) == 0
    assert File.read!("examples/sshd_config_hardened") |> audit() == []
  end
end
