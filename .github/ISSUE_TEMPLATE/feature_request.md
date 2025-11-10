name: Feature request
labels: [enhancement]
assignees: []
title: "[feat]: "
body:
  - type: textarea
    id: summary
    attributes:
      label: Summary
      description: What problem does this solve? What is the user story?
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposed solution
      description: API/CLI changes, flags, data contracts
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
  - type: input
    id: out-of-scope
    attributes:
      label: Out of scope
