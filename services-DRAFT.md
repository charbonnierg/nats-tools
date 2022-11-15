It would be awesome to use all those accounts.

It would really demonstrate the capabilities of the QUARA platform.

That being said, reallistically, it would be a hell to manage 😅

We mainly perform single-node deployments, it brings too much complexity to store/configure/read all the necessary keypaits

Conclusion: We need to automate credentials fetching.

The easiest solution is to:
    - Run a QUARA agent on each host machine.
        => Agent is responsible for storing creds
        => Agent is configured to run:
            - For an account (identified by account public key)
            - For a server (identified by user public key)
        => Agent has a signing key for each account (BLE, ML, OPCUA, ...) which can only sign users for the agent public key.
        => This way, app authenticate using the identity of the "agent" within their accounts.
        => Agent generates keypairs for each user account
        => Agent signs JWT for each user account
        => Agent stores JWT
        => NOTE: Agent CANNOT revoke user, in order to do that, agent should also have an operator signing key. While granting an operator signing key can be achieved without compromising other accounts, it would greatly complicate things.
        => NOTE: In order to revoke user, NATS topology must be extended to the cloud.
        => Some periodic job can check JWT state on disk


# QUARA Issuer

Can issue:

- Scoped account signing keys
- Account JWT
- User JWT

In order to do that, it needs an operator signing key.

- Operator signing key is used to generate account JWT.

- Unscoped Account Signing keys are generated for each account. Those keys are used to sign users.

- A QUARA Agent can requests for a scoped signing account