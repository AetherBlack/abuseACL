![](./.github/banner.png)

<p align="center">
    A python script to automatically list vulnerable Windows ACEs/ACLs.
    <br>
    <img alt="PyPI" src="https://img.shields.io/pypi/v/abuseACL">
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/AetherBlack/abuseACL">
    <a href="https://twitter.com/intent/follow?screen_name=san__yohan" title="Follow"><img src="https://img.shields.io/twitter/follow/san__yohan?label=AetherBlack&style=social"></a>
    <br>
</p>

## Installation

You can install it from pypi (latest version is <img alt="PyPI" src="https://img.shields.io/pypi/v/abuseACL">) with this command:

```bash
sudo python3 -m pip install abuseACL
```

OR from source :

```bash
git clone https://github.com/AetherBlack/abuseACL
cd abuseACL
sudo python3 -m pip install -r requirements.txt
sudo python3 setup.py install
```

## Examples

- You want to list vulnerable ACEs/ACLs for the current user :

```bash
abuseACL CONTOSO/User:'Password'@dc01.contoso.intra
```

- You want to list vulnerable ACEs/ACLs for another user/computer/group :

```bash
abuseACL -principal Aether CONTOSO/User:'Password'@dc01.contoso.intra
```

- You want to list vulnerable ACEs/ACLs for a list of users/computers/groups :

```bash
abuseACL -principalsfile accounts.txt CONTOSO/User:'Password'@dc01.contoso.intra
```

You can then use [dacledit](https://github.com/ThePorgs/impacket/blob/master/examples/dacledit.py) to exploit the ACEs.

---

## Credits

- [@_nwodtuhs](https://twitter.com/_nwodtuhs) for the helpful [DACL](https://www.thehacker.recipes/a-d/movement/dacl) documentation
- [@fortra](https://github.com/fortra/) for developping [impacket](https://github.com/fortra/impacket)

## License

[GNU General Public License v3.0](./LICENSE)
