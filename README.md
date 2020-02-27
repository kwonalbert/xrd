# XRD

XRD (short for Crossroads) is a metadata point-to-point messaging
system that allows users to exchange fixed sized messages in a way
that doesn't reveal anything about their communication pattern.
End-to-end communication does a great job of protecting the content of
the messages, but sometimes, encryption alone is insufficient due to
*metadata* leakages. For instance, for whistleblowing, just the fact
that a government official talked to a journalist might be enough to
get them into trouble (and the standard encryption does not protect
this sort of communication metadata). XRD is designed to protect these
sort of metadata as well as the actual content of the conversation.
The details of the system is explained in our [NSDI'20 paper][paper].

If you have any questions or issues with this code, please contact
us at `kwonal [at] mit.edu`.

*The code posted here is a research prototype. While the code performs
all the necessary crypto operations and should be fairly accurate in
terms of performance, it is likely full of security bugs and
security-criticial TODOs that hasn't been addressed. Pleae be careful
if any part of this code is reused for real-world projects.*

[paper]: https://www.usenix.org/conference/nsdi20/presentation/kwon

## Code organization and usage

To see how the different modules fit together, please look at
`xrd_test.go`: it creates a local test consisting of a small number
of mix chains and a small number of users. The code at a high level
is organized as follows.

* client: Code that simulates many clients. It generates batches of
  realistic looking clients messages.
* config: Common code that's used to configure various servers.
* coordinator: A simple coordinator that connects to all servers for
  running experiments.
* mailbox: A simple mailbox that supports put and get functionality.
* mixnet: All the code related to actual mixing operation of the
  system. Also contains the verifiable mixnet (aggregate hybrid
  shuffle) code.
* server: Wrapper code around mixnet to handle setting up the network,
  and starting and stopping rounds.

To run this with non-go tests, you can use the configuration generator
in `cmd/config` to generate network configurations, and configure the
servers and clients using the generated config files. There is also a
sample `run_experiment.py` in scripts directory which can be used to
run experiments remotely using SSH to coordinate the servers, assuming
the list of server IPs are saved in a file called `remote_ips`.
