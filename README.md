# wonderland

wonderland is a conceptual art project exploring [cyberpunk](https://www.dnalounge.com/backstage/log/2025/06/06.html) [anemoia](https://www.dictionaryofobscuresorrows.com) among the burned out ashes of the AI culture war

# installation

go install

# server

```
mkdir -p ~/.config/wonderland
cp config.yaml.example ~/.config/wonderland/config.yaml
vim ~/.config/wonderland/config.yaml
vim ~/.config/wonderland/authorized_keys # OpenSSH format
vim ~/.config/wonderland/admin_keys # same as authorized keys, but they get admin powers

wonderland
```

## server config

```
wifi:
  ssid: "SSID of your local WiFi"
  password: "Password for your local WiFi"

tunnel:
  host: "IPv4 or IPv6 to a reverse proxy host that has a globally reachable IPv6 address"
  port: "SSH port to connect to reverse proxy
  user: "SSH user to connect to reverse proxy"
  key_file: "path to a private key file you can use to authenticate with reverse proxy"
  remote_port: "port to make visible on globally visible reverse proxy"
  local_port: "port to run wonderland on locally"

wish:
  port: "port to run wonderland on locally"
  host_key: "path to wonderland server private key, will be created if missing"
  authorized_keys: "path to public keys for authorized users"
  admin_keys: "path to public keys for admin users (must also be in authorized_keys)"
```
The wonderland server runs locally and appears to the world through the globally addressable SSH server. This can be any SSH server that has a public IPv6 address. You can connect to the reverse proxy using either IPv4 or IPv6, but wonderland public server addresses are always IPv6. You must also specify a port as the default port 22 is not assumed since it is often going to be in use to connect to the reverse proxy.

A reverse proxy is always used, even if you are running wonderland on a cloud server that has a public IPv6 address. This is so that cloud providers can't steal our data and use it to train AIs. All data is truly end-to-end encrypted, by which I mean encrypted between the wonderland client and the wonderland server (which is running locally). The cloud providers can't see any data. If you already have a local IPv6 address that is globally routable, congratluations, that's awesome. Do you really want to tell everyone what it is, though? Also, this IP needs to be static as it is your server's identity. No DNS or DHTs or anything like that is used. You need the IP, port, and public key of a server to connect to it.

# client

To connect to a server, first add it to the server database with "wonderland add". For this, you need it's IPv6 address, port, and SSH public key. You also need to give it a name because IPv6 addresses are pretty long. After you have named it, you can connect with "wonderland connect". There is no "trust on first use", you must have the server's public key to add a server. Get this from whomever gave you the IP and port.

What if you don't have IPv6 connectivity? That's unfortunate, and if I were you I would complain. However, you can also use a bastion host. This can be any machine whose IP you can reach that also has IPv6 connectivity. See the "wonderland add" help for more information on specifying a bastion host.

In order to connect, your public key must already be in the server's authorized_keys file. Have the server admin take care of this when they give you the server IP, port, and public key.

# usage

It's art. 🤷‍♂️
