defmodule SshConfigAudit.CLI do
  @usage "usage: ssh-config-audit <sshd_config> [--html] [--fail-below SCORE]\nExit: 0 ok, 1 score below --fail-below, 2 bad input.\n"

  def main(args) do
    case args do
      [path | rest] when binary_part(path, 0, 1) != "-" -> run(path, rest)
      _ -> usage_error()
    end
  end

  defp run(path, rest) do
    {opts, extra, bad} = OptionParser.parse(rest, strict: [html: :boolean, fail_below: :integer])

    cond do
      bad != [] or extra != [] -> usage_error()
      true ->
        case File.read(path) do
          {:ok, text} ->
            findings = SshConfigAudit.audit(text)
            IO.write(if opts[:html], do: SshConfigAudit.render_html(findings, Path.basename(path)), else: SshConfigAudit.render_text(findings))
            if opts[:fail_below] && SshConfigAudit.score(findings) < opts[:fail_below], do: System.halt(1)

          {:error, reason} ->
            IO.puts(:stderr, "error: cannot read #{path}: #{:file.format_error(reason)}")
            System.halt(2)
        end
    end
  end

  defp usage_error do
    IO.write(:stderr, @usage)
    System.halt(2)
  end
end
