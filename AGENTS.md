AI IS NOT ALLOWED TO EDIT THIS FILE ONLY HUMANS CAN!

# Orchestrator
- This is a tailor made kubernetes alternative specially made for TerraScale
- It needs to manage all of its regions Oracle Cloud resources
- Each region will have its own orchestrator/nats cluster

# Rules
- This project needs to use C#
- This needs to be deployed as a single binary to be easy to deployed and updated
- Commit and push often after every major change automatically
- When the human asks for a commit, commit and push exactly as asked — do not run tests, checks, or builds first

# Libraries
- We should use nats for ts-orchestrator <-> ts-orchestrator comunnication
- We should use TUnit for tests
