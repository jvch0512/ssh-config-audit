defmodule SshConfigAudit.MixProject do
  use Mix.Project

  def project do
    [
      app: :ssh_config_audit,
      version: "1.0.0",
      elixir: "~> 1.14",
      escript: [main_module: SshConfigAudit.CLI, name: "ssh-config-audit"],
      deps: []
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
