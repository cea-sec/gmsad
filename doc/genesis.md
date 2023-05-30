# Why was this tool created ?

Suppose we have a pool of Linux servers working together for redundancy or load balancing. These servers authenticate users using Kerberos. Users may hit one server or another without distinction. Everything has to work as long as at least one of the servers in the pool is up. In this situation, all servers must share a keytab containing the secret of the service account used to authenticate users. This is perfectly fine, unless your security team asks you to change the service account secret periodically, which will result in updating the keytab on all servers. The update can be done manually, but it is very likely to lead to indisponibility or errors.

To solve this problem, the first approach was to select one server as the "master". The "master" will be responsible for managing the keytab, updating it using kpasswd and deploying it to all the other servers. But, what happens if the master is down? The password won't be renewed and will expire, resulting in all users being unable to authenticate.

There are multiple problems:
1. How to choose which server is master?
2. How to ensure that the master server is always alive?
3. How to share the secret reliably between all servers?

It would have taken a bit more development to solve these problems. Fortunately for us, Microsoft has a mechanism in Active Directory that solves all our problems: group Managed Service Account, also known as gMSA.

gMSAs are accounts whose passwords are managed by the Active Directory domain controllers and can be accessed by authorised computer accounts. For more details about gMSA see [How does a gMSA work ?](gmsa.md).

## How using gMSAs account helps to solve our problems?

Let say that each Linux server in the pool has its own computer account in Active Directory and is responsible for renewing its secret (similarly to a Windows server), using for example msktutil (https://github.com/msktutil/msktutil). The SPN of the service is owned by a gMSA. Each server account in AD has the right to retrieve the secret of the gMSA.

Thus, each server is able to retrieve the secret of the gMSA account and can generate a valid keytab for its SPN.

Unfortunately, there was no tool available to use these gMSA from Linux. That is why we developped `gmsad`.
