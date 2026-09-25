AI IS NOT ALLOWED TO EDIT THIS FILE ONLY HUMANS CAN!

# Orchestrator
- This is a tailor made kubernetes alternative specially made for TerraScale
- It needs to manage all of its regions Oracle Cloud resources
- Each region will have its own orchestrator/nats cluster
- Let's use embedded NATS
- Each regions MUST auto form cluster automagically
- The orchestrator MUST scale terrabase up and down as neeeded

# Rules
- This project MUST to use GO
- This MUST to be deployed as a single binary to be easy to deployed and updated
- Commit and push often after every major change automatically
- The project must follow a feature sliced design so it is well organized and similar or dependant files and services are kept together

# Libraries
- We should use nats for ts-orchestrator <-> ts-orchestrator comunnication