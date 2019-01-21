Key Generator for AWS CLI Access

Language: Python 2.7

Description:

* Script generates assumedRole.pkl storing AWS credentials. It's used for comparing timestamps and generating AWS credentials file.

* Credentials file is stored in User profile ~/.aws directory.

* If Credentials are going to expire in <5 minutes, user needs to provide UID/Token/Password again

# User configuration
You can configure a default user. You need to create a file `~/.aws/user` containing just the username.

Example of `~/.aws/user` for username `ab123`

```
ab123
```


