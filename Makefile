build:
	mix escript.build

test:
	mix test

sample: build
	./ssh-config-audit examples/sshd_config_legacy > docs/sample-output.txt
	./ssh-config-audit examples/sshd_config_legacy --html > site/index.html
