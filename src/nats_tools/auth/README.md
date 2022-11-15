# NATS Auth

> Manage NATS operators and accounts.

### NATS Sys client

#### **Subjects always available**

| Subjects to publish requests to        | Description                                                                             | Message Output        |
| -------------------------------------- | --------------------------------------------------------------------------------------- | --------------------- |
| `$SYS.REQ.SERVER.PING.STATZ`           | Exposes the `STATZ` HTTP monitoring endpoint, each server will respond with one message | Same as HTTP endpoint |
| `$SYS.REQ.SERVER.PING.VARZ`            | - same as above for - `VARZ`                                                            | - same as above -     |
| `$SYS.REQ.SERVER.PING.SUBZ`            | - same as above for - `SUBZ`                                                            | - same as above -     |
| `$SYS.REQ.SERVER.PING.CONNZ`           | - same as above for - `CONNZ`                                                           | - same as above -     |
| `$SYS.REQ.SERVER.PING.ROUTEZ`          | - same as above for - `ROUTEZ`                                                          | - same as above -     |
| `$SYS.REQ.SERVER.PING.GATEWAYZ`        | - same as above for - `GATEWAYZ`                                                        | - same as above -     |
| `$SYS.REQ.SERVER.PING.LEAFZ`           | - same as above for - `LEAFZ`                                                           | - same as above -     |
| `$SYS.REQ.SERVER.PING.ACCOUNTZ`        | - same as above for - `ACCOUNTZ`                                                        | - same as above -     |
| `$SYS.REQ.SERVER.PING.JSZ`             | - same as above for - `JSZ`                                                             | - same as above -     |
| `$SYS.REQ.SERVER.<server-id>.STATZ`    | Exposes the `STATZ` HTTP monitoring endpoint, only requested server responds            | Same as HTTP endpoint |
| `$SYS.REQ.SERVER.<server-id>.VARZ`     | - same as above for - `VARZ`                                                            | - same as above -     |
| `$SYS.REQ.SERVER.<server-id>.SUBZ`     | - same as above for - `SUBZ`                                                            | - same as above -     |
| `$SYS.REQ.SERVER.<server-id>.CONNZ`    | - same as above for - `CONNZ`                                                           | - same as above -     |
| `$SYS.REQ.SERVER.<server-id>.ROUTEZ`   | - same as above for - `ROUTEZ`                                                          | - same as above -     |
| `$SYS.REQ.SERVER.<server-id>.GATEWAYZ` | - same as above for - `GATEWAYZ`                                                        | - same as above -     |
| `$SYS.REQ.SERVER.<server-id>.LEAFZ`    | - same as above for - `LEAFZ`                                                           | - same as above -     |
| `$SYS.REQ.SERVER.<server-id>.ACCOUNTZ` | - same as above for - `ACCOUNTZ`                                                        | - same as above -     |
| `$SYS.REQ.SERVER.<server-id>.JSZ`      | - same as above for - `JSZ`                                                             | - same as above -     |
| `$SYS.REQ.ACCOUNT.<account-id>.SUBSZ`  | Exposes the `SUBSZ` HTTP monitoring endpoint, filtered by account-id.                   | Same as HTTP endpoint |
| `$SYS.REQ.ACCOUNT.<account-id>.CONNZ`  | - same as above for `CONNZ` -                                                           | - same as above -     |
| `$SYS.REQ.ACCOUNT.<account-id>.LEAFZ`  | - same as above for `LEAFZ` -                                                           | - same as above -     |
| `$SYS.REQ.ACCOUNT.<account-id>.JSZ`    | - same as above for `JSZ` -                                                             | - same as above -     |
| `$SYS.REQ.ACCOUNT.<account-id>.CONNS`  | Exposes the event `$SYS.ACCOUNT.<account-id>.SERVER.CONNS` as request                   | - same as above -     |
| `$SYS.REQ.ACCOUNT.<account-id>.INFO`   | Exposes account specific information similar to `ACCOUNTZ`                              | Similar to `ACCOUNTZ` |

Each of the subjects can be used without any input. However, for each request type (`STATZ`, `VARZ`, `SUBSZ`, `CONNS`, `ROUTEZ`, `GATEWAYZ`, `LEAFZ`, `ACCOUNTZ`, `JSZ`) a json with type specific options can be sent. Furthermore all subjects allow for filtering by providing these values as json:

| Option        | Effect                                               |
| ------------- | ---------------------------------------------------- |
| `server_name` | Only server with matching server name will respond.  |
| `cluster`     | Only server with matching cluster name will respond. |
| `host`        | Only server running on that host will respond.       |
| `tags`        | Filter responders by tags. All tags must match.      |

#### **Subjects available when using NATS-based resolver**

| Subject                                       | Description                                                                              | Input                                                                                       | Output                                                                                         |
| --------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `$SYS.REQ.ACCOUNT.<account-id>.CLAIMS.UPDATE` | Update a particular account JWT (only possible if properly signed)                       | JWT body                                                                                    |                                                                                                |
| `$SYS.REQ.ACCOUNT.<account-id>.CLAIMS.LOOKUP` | Responds with requested JWT                                                              |                                                                                             | JWT body                                                                                       |
| `$SYS.REQ.CLAIMS.PACK`                        | Single responder compares input, sends all JWT if different.                             | xor of all sha256(stored-jwt). Send empty message to download all JWT.                      | If different, responds with all stored JWT (one message per JWT). Empty message to signify EOF |
| `$SYS.REQ.CLAIMS.LIST`                        | Each server responds with list of account ids it stores                                  |                                                                                             | list of account ids separated by newline                                                       |
| `$SYS.REQ.CLAIMS.UPDATE`                      | Exposes $SYS.REQ.ACCOUNT..CLAIMS.UPDATE without the need for `<account-id>`              | JWT body                                                                                    |                                                                                                |
| `$SYS.REQ.CLAIMS.DELETE`                      | When the resolver is configured with `allow_delete: true`, deleting accounts is enabled. | Generic operator signed JWT claim with a field `accounts` containing a list of account ids. |                                      

#### Advisories

JetStream publishes a number of advisories that can inform operations about the health and the state of the Streams. These advisories are published to normal NATS subjects below `$JS.EVENT.ADVISORY.>` and one can store these advisories in JetStream Streams if desired.

The command `nats event --js-advisory` can view all these events on your console. The Golang package [jsm.go](https://github.com/nats-io/jsm.go) can consume and render these events and have data types for each of these events.

All these events have JSON Schemas that describe them, schemas can be viewed on the CLI using the `nats schema show <schema kind>` command.

| Description                                 | Subject | Kind                                                    |
|:--------------------------------------------| :--- |:--------------------------------------------------------|
| API interactions                            | `$JS.EVENT.ADVISORY.API` | `io.nats.jetstream.advisory.v1.api_audit`               |
| Stream CRUD operations                      | `$JS.EVENT.ADVISORY.STREAM.CREATED.<STREAM>` | `io.nats.jetstream.advisory.v1.stream_action`           |
| Consumer CRUD operations                    | `$JS.EVENT.ADVISORY.CONSUMER.CREATED.<STREAM>.<CONSUMER>` | `io.nats.jetstream.advisory.v1.consumer_action`         |
| Snapshot started using `nats stream backup` | `$JS.EVENT.ADVISORY.STREAM.SNAPSHOT_CREATE.<STREAM>` | `io.nats.jetstream.advisory.v1.snapshot_create`         |
| Snapshot completed                          | `$JS.EVENT.ADVISORY.STREAM.SNAPSHOT_COMPLETE.<STREAM>` | `io.nats.jetstream.advisory.v1.snapshot_complete`       |
| Restore started using `nats stream restore` | `$JS.EVENT.ADVISORY.STREAM.RESTORE_CREATE.<STREAM>` | `io.nats.jetstream.advisory.v1.restore_create`          |
| Restore completed                           | `$JS.EVENT.ADVISORY.STREAM.RESTORE_COMPLETE.<STREAM>` | `io.nats.jetstream.advisory.v1.restore_complete`        |
| Consumer maximum delivery reached           | `$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES.<STREAM>.<CONSUMER>` | `io.nats.jetstream.advisory.v1.max_deliver`             |
| Message delivery naked using AckNak         | `$JS.EVENT.ADVISORY.CONSUMER.MSG_NAKED.<STREAM>.<CONSUMER>` | `io.nats.jetstream.advisory.v1.nak`                     |
| Message delivery terminated using AckTerm   | `$JS.EVENT.ADVISORY.CONSUMER.MSG_TERMINATED.<STREAM>.<CONSUMER>` | `io.nats.jetstream.advisory.v1.terminated`              |
| Message acknowledged in a sampled Consumer  | `$JS.EVENT.METRIC.CONSUMER.ACK.<STREAM>.<CONSUMER>` | `io.nats.jetstream.metric.v1.consumer_ack`              |
| Clustered Stream elected a new leader       | `$JS.EVENT.ADVISORY.STREAM.LEADER_ELECTED.<STREAM>` | `io.nats.jetstream.advisory.v1.stream_leader_elected`   |
| Clustered Stream lost quorum                | `$JS.EVENT.ADVISORY.STREAM.QUORUM_LOST.<STREAM>` | `io.nats.jetstream.advisory.v1.stream_quorum_lost`      |
| Clustered Consumer elected a new leader     | `$JS.EVENT.ADVISORY.CONSUMER.LEADER_ELECTED.<STREAM>.<CONSUMER>` | `io.nats.jetstream.advisory.v1.consumer_leader_elected` |
| Clustered Consumer lost quorum              | `$JS.EVENT.ADVISORY.CONSUMER.QUORUM_LOST.<STREAM>.<CONSUMER>` | `io.nats.jetstream.advisory.v1.consumer_quorum_lost`    |