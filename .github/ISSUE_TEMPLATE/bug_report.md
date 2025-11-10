name: Bug report
labels: [bug]
assignees: []
title: "[bug]: "
body:
  - type: textarea
    id: description
    attributes:
      label: Describe the bug
      description: What happened? What did you expect?
    validations:
      required: true
  - type: input
    id: target
    attributes:
      label: Target URL (if applicable)
      description: Example target for reproduction
  - type: textarea
    id: steps
    attributes:
      label: Steps to reproduce
      value: |
        1. ...
        2. ...
        3. ...
  - type: textarea
    id: logs
    attributes:
      label: Logs / output
      render: shell
  - type: input
    id: version
    attributes:
      label: Version
      placeholder: main
