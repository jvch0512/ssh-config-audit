defmodule SshConfigAudit do
  @moduledoc """
  Audits an sshd_config against a hardening baseline. Elixir standard library only.

  OpenSSH uses the first value it finds for a keyword (outside Match blocks), and keyword
  names are case-insensitive. Both rules are implemented here, because getting them wrong
  produces false reports.
  """

  defmodule Finding do
    @enforce_keys [:rule, :severity, :message]
    defstruct [:rule, :severity, :message, :line, :fix]
  end

  @weak_ciphers ~w(3des-cbc arcfour arcfour128 arcfour256 blowfish-cbc cast128-cbc aes128-cbc aes192-cbc aes256-cbc)
  @weak_macs ~w(hmac-md5 hmac-md5-96 hmac-sha1 hmac-sha1-96 umac-64@openssh.com hmac-ripemd160)
  @weak_kex ~w(diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1)

  @doc "Parses config text into `%{keyword => {value, line}}`, first occurrence wins, Match blocks ignored."
  def parse(text) when is_binary(text) do
    text
    |> String.split(~r/\r?\n/)
    |> Enum.with_index(1)
    |> Enum.reduce_while(%{}, fn {raw, n}, acc ->
      line = raw |> String.split("#", parts: 2) |> hd() |> String.trim()

      cond do
        line == "" ->
          {:cont, acc}

        String.match?(line, ~r/^match\s/i) ->
          {:halt, acc}

        true ->
          case String.split(line, ~r/[\s=]+/, parts: 2) do
            [key, value] -> {:cont, Map.put_new(acc, String.downcase(key), {String.trim(value), n})}
            _ -> {:cont, acc}
          end
      end
    end)
  end

  @doc "Runs every check and returns findings sorted by severity."
  def audit(text) do
    cfg = parse(text)

    [
      &root_login/1, &password_auth/1, &empty_passwords/1, &protocol/1, &crypto/1, &x11/1,
      &max_auth_tries/1, &user_env/1, &forwarding/1, &log_level/1, &allow_list/1, &rhosts/1, &strict_modes/1
    ]
    |> Enum.flat_map(& &1.(cfg))
    |> Enum.sort_by(&{severity_rank(&1.severity), &1.rule})
  end

  def severity_rank(:critical), do: 0
  def severity_rank(:high), do: 1
  def severity_rank(:medium), do: 2

  @doc "0..100, higher is better."
  def score(findings) do
    penalty = Enum.reduce(findings, 0, fn f, acc -> acc + %{critical: 30, high: 15, medium: 5}[f.severity] end)
    max(0, 100 - penalty)
  end

  def grade(score) when score >= 90, do: "A"
  def grade(score) when score >= 75, do: "B"
  def grade(score) when score >= 60, do: "C"
  def grade(score) when score >= 40, do: "D"
  def grade(_), do: "F"

  defp val(cfg, key), do: with({v, _} <- Map.get(cfg, key), do: String.downcase(v))
  defp line(cfg, key), do: with({_, n} <- Map.get(cfg, key), do: n)
  defp finding(rule, sev, msg, line, fix), do: %Finding{rule: rule, severity: sev, message: msg, line: line, fix: fix}

  defp root_login(cfg) do
    case val(cfg, "permitrootlogin") do
      "yes" -> [finding("SSH001", :critical, "root can log in over SSH with a password", line(cfg, "permitrootlogin"), "PermitRootLogin no")]
      _ -> []
    end
  end

  defp password_auth(cfg) do
    case val(cfg, "passwordauthentication") do
      "no" -> []
      nil -> [finding("SSH002", :high, "PasswordAuthentication is not set and defaults to yes: passwords can be brute-forced", nil, "PasswordAuthentication no")]
      _ -> [finding("SSH002", :high, "password logins are enabled: passwords can be brute-forced", line(cfg, "passwordauthentication"), "PasswordAuthentication no")]
    end
  end

  defp empty_passwords(cfg) do
    if val(cfg, "permitemptypasswords") == "yes",
      do: [finding("SSH003", :critical, "accounts with empty passwords can log in", line(cfg, "permitemptypasswords"), "PermitEmptyPasswords no")],
      else: []
  end

  defp protocol(cfg) do
    case val(cfg, "protocol") do
      v when v in ["1", "2,1", "1,2"] -> [finding("SSH004", :critical, "SSH protocol 1 is allowed and is broken", line(cfg, "protocol"), "Protocol 2")]
      _ -> []
    end
  end

  defp crypto(cfg) do
    for {key, weak, label} <- [{"ciphers", @weak_ciphers, "cipher"}, {"macs", @weak_macs, "MAC"}, {"kexalgorithms", @weak_kex, "key exchange"}],
        v = val(cfg, key),
        bad = v |> String.trim_leading("+") |> String.split(",", trim: true) |> Enum.map(&String.trim/1) |> Enum.filter(&(&1 in weak)),
        bad != [] do
      finding("SSH005", :medium, "weak #{label} enabled: #{Enum.join(bad, ", ")}", line(cfg, key), "remove the weak entries or drop the #{key} line to use the modern defaults")
    end
  end

  defp x11(cfg) do
    if val(cfg, "x11forwarding") == "yes",
      do: [finding("SSH006", :medium, "X11 forwarding is on and widens the attack surface of a server", line(cfg, "x11forwarding"), "X11Forwarding no")],
      else: []
  end

  defp max_auth_tries(cfg) do
    case val(cfg, "maxauthtries") do
      nil -> []
      v ->
        case Integer.parse(v) do
          {n, _} when n > 4 -> [finding("SSH007", :medium, "MaxAuthTries is #{n}: too many guesses per connection", line(cfg, "maxauthtries"), "MaxAuthTries 3")]
          _ -> []
        end
    end
  end

  defp user_env(cfg) do
    if val(cfg, "permituserenvironment") == "yes",
      do: [finding("SSH008", :high, "users can set environment variables, which can bypass restrictions", line(cfg, "permituserenvironment"), "PermitUserEnvironment no")],
      else: []
  end

  defp forwarding(cfg) do
    for {key, msg} <- [{"gatewayports", "GatewayPorts exposes forwarded ports to the whole network"}, {"allowtcpforwarding", "TCP forwarding lets any user build tunnels through this host"}],
        val(cfg, key) in ["yes", "all", "clientspecified"] do
      finding("SSH009", :medium, msg, line(cfg, key), "#{key} no")
    end
  end

  defp log_level(cfg) do
    if val(cfg, "loglevel") in ["quiet", "fatal", "error"],
      do: [finding("SSH010", :medium, "LogLevel #{val(cfg, "loglevel")} hides failed logins and key use", line(cfg, "loglevel"), "LogLevel VERBOSE")],
      else: []
  end

  defp allow_list(cfg) do
    if Enum.any?(["allowusers", "allowgroups"], &Map.has_key?(cfg, &1)),
      do: [],
      else: [finding("SSH011", :medium, "no AllowUsers or AllowGroups: every local account may try to log in", nil, "AllowGroups ssh-users")]
  end

  defp rhosts(cfg) do
    for {key, bad, msg} <- [{"hostbasedauthentication", "yes", "host-based authentication trusts other machines"}, {"ignorerhosts", "no", ".rhosts files are honoured"}],
        val(cfg, key) == bad do
      finding("SSH012", :high, msg, line(cfg, key), "#{key} #{if bad == "yes", do: "no", else: "yes"}")
    end
  end

  defp strict_modes(cfg) do
    if val(cfg, "strictmodes") == "no",
      do: [finding("SSH013", :high, "StrictModes is off: unsafe file permissions on keys are accepted", line(cfg, "strictmodes"), "StrictModes yes")],
      else: []
  end

  # ---- output ----

  def render_text(findings) do
    s = score(findings)
    head = "grade #{grade(s)}, score #{s}/100, #{length(findings)} findings\n"

    body =
      Enum.map_join(findings, "", fn f ->
        at = if f.line, do: " (line #{f.line})", else: " (not set)"
        "#{String.upcase(to_string(f.severity))}#{String.duplicate(" ", 9 - String.length(to_string(f.severity)))}#{f.rule}#{at}\n         #{f.message}\n         fix: #{f.fix}\n"
      end)

    head <> body
  end

  defp esc(s), do: s |> String.replace("&", "&amp;") |> String.replace("<", "&lt;") |> String.replace(">", "&gt;") |> String.replace("\"", "&quot;")

  def render_html(findings, title) do
    s = score(findings)

    rows =
      Enum.map_join(findings, "", fn f ->
        at = if f.line, do: "line #{f.line}", else: "not set"
        "<tr><td class=\"#{f.severity}\">#{f.severity}</td><td>#{f.rule}</td><td>#{at}</td><td>#{esc(f.message)}<br><code>#{esc(f.fix || "")}</code></td></tr>"
      end)

    """
    <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>ssh-config-audit</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}.grade{font-size:42px;font-weight:800}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}.critical{color:#f85149;font-weight:700}.high{color:#f0883e;font-weight:700}.medium{color:#e3b341;font-weight:700}code{color:#7ee787}</style></head><body><h1>ssh-config-audit</h1><p class="sub">sshd_config hardening audit in Elixir, standard library only. Sample: #{esc(title)} (synthetic).</p><p><span class="grade">#{grade(s)}</span> &nbsp; score #{s}/100, #{length(findings)} findings</p><table><tr><th>Severity</th><th>Rule</th><th>Where</th><th>Finding and fix</th></tr>#{rows}</table><p class="sub">Reads the file, not the running daemon: check `sshd -T` for the effective settings, and note that Match blocks are not evaluated.</p></body></html>
    """
  end
end
