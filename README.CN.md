syncrypto - 文件夹加密双向同步
==============================

[![最新版本](https://img.shields.io/pypi/v/syncrypto.svg)](https://pypi.python.org/pypi/syncrypto/)[![集成测试](https://travis-ci.org/liangqing/syncrypto.svg?branch=master)](https://travis-ci.org/liangqing/syncrypto)[![代码覆盖率](https://codecov.io/github/liangqing/syncrypto/coverage.svg?branch=master)](https://codecov.io/github/liangqing/syncrypto?branch=master)[![代码健康度](https://landscape.io/github/liangqing/syncrypto/master/landscape.svg?style=flat)](https://landscape.io/github/liangqing/syncrypto/master)


## 介绍

`syncrypto`可以用来将一个文件夹里面所有文件同步到另外一个加密的文件夹中，
一般来说，可以这样使用：

```
                 syncrypto                         syncrypto
文件夹A  <---------------------> 加密文件夹B <-------------------> 文件夹C
 机器X              (可以放在不安全的地方，例如云存储)                机器Y

```

加密文件夹B中的文件都是加密过的，所以可以把它放在不怎么安全的地方（例如云盘，公共硬盘等）

明文文件和加密文件是一一对应的关系，所以每次同步只会添加（删除/修改）那些需要的文件，这样
很适合那些基于文件系统的同步工具，例如云盘、rsync等。

同步过程是双向的，所以，文件不仅仅是从明文文件夹同步到加密文件夹，同样也会从加密文件夹同步到
明文文件夹，`syncrypto`会根据算法选择最新的。

如果有冲突的话，`syncrypto`会将明文文件重命名（加上单词conflict），然后将密文文件同步过来

`syncrypto`是不会删除文件的，如果同步过程中需要删除或者覆盖文件，`syncrypto`会将文件移动
到废纸篓里面。密文文件夹的废纸篓在_syncrypto/trash下，明文文件夹的废纸篓在
.syncrypto/trash下。密文文件夹废纸篓里面的文件一样是加密过的。

## 安装

### 支持的平台和系统

`syncrypto`支持python2, python3，并且在下面的平台下[测试](https://travis-ci.org/liangqing/syncrypto)通过：

* python2.6
* python2.7
* python3.3
* python3.4

支持Windows，Linux，OS X

### 安装依赖

**如果是Windows的话，可以直接跳过**

由于依赖[cryptography](https://github.com/pyca/cryptography)，在*Linux*上需要先安装一些依赖: 

在Debian/Ubuntu系列中运行
```bash
sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```
或者，在Fedora/RHEL系列中运行
```bash
sudo yum install gcc libffi-devel python-devel openssl-devel
```

如果是OS X系统，需要运行
```bash
xcode-select --install
```

### 安装

安装完所有依赖后，即可通过[pip](https://pip.pypa.io/en/latest/installing.html)
安装``syncrypto``:

```bash
pip install syncrypto
```


## 使用

### 同步

```bash
syncrypto [加密文件夹] [明文文件夹] # 注意，加密文件夹放在前面
```
可以使用这个命令来同步，运行后会提示输入密码，第一次在该加密目录下运行的话是设置密码，之后
运行的话会进行密码匹配，如果不匹配则不能进行同步（放心，`syncrypto`不会保存明文的密码）

如果不想通过命令行交互的方式输入密码，可以通过--password-file选项来通过文件给出密码：

```bash
syncrypto [加密文件夹] [明文文件夹] --password-file [密码文件]
```
密码文件里面保存的是明文密码

### 为同步添加rule

有时候，有些文件（例如一些临时文件）没有必要进行加密同步，这个时候你可以通过rule来排除
这些文件:

```bash
syncrypto [加密文件夹] [明文文件夹] --rule 'ignore: name match *.swp'
```
上面这条命令会在同步过程中忽略那些文件名匹配"*.swp"的文件

可以添加多条rule：

```bash
syncrypto [加密文件夹] [明文文件夹] --rule 'include: name eq README.md' --rule 'ignore: name match *.md'
```

上面这条命令会在同步过程中忽略那些文件名匹配"*.md"的文件，但是保留文件名为"README.md"的文件。

如果有多条rule的话，会按照顺序优先选择第一条匹配的rule

也可以通过文件，而不是命令行的方式配置rule，--rule-file选项可以做到：

```bash
syncrypto [加密文件夹] [明文文件夹] --rule-file [rule文件]
```

rule文件可以这样写：

```
include: name eq README.md

# ignore all markdown files, this is a comment
ignore: name match *.md
```

默认的--rule-file指向`[明文文件夹]/.syncrypto/rules`

如果同时给定了--rule, --rule-file选项，那会--rule指定的规则优先级更高。


rule的格式：
```
[action]: [file attribute] [operand] [value]
```

`[action]`是指匹配规则后的动作，可以为'include', 'ignore', 'exclude'。

'include'表示包含，'ignore'表示忽略，'exclude'和ignore是同样的含义

`[file attribute]`是指参与匹配的文件的属性，支持：

* `name`, 文件名，包括扩展名
* `path`, 文件路径，从明文文件夹的根目录算起，例如 "a/b/c.txt"
* `size`, 文件大小
* `ctime`, 文件的change time（windows下指的是创建时间）
* `mtime`, 文件的修改时间

`[operand]`:
* `eq`, `==`
* `gt`, `>`
* `lt`, `<`
* `gte`, `>=`
* `lte`, `<=`
* `ne`, `!=`, `<>`
* `match`, 通配符匹配
* `regexp`, 正则表达式匹配

`[value]` 就是参与比较或者匹配的值，如果operand是size的话，默认单位是字节，可以带单位，
例如K,M,G; 2K表示2048字节。

如果是`ctime`, `mtime`的话，时间的格式是："%Y-%m-%d %H:%M:%S"

### 加密一个文件

如果只想加密一个文件，可以使用：

```bash
syncrypto --encrypt-file [文件路径]
```

这条命令默认会将加密后的文件放在明文文件相同目录下，如果想放到别的地方，可以加上--out-file
参数:

```bash
syncrypto --encrypt-file [明文文件路径] --out-file [加密后文件路径]
```

### 解密一个文件

如果想解密任何一个通过``syncrypto``加密过的文件，可以使用：

```bash
syncrypto --decrypt-file [文件路径]
```

这条命令默认会将解密后的文件放在**当前目录下**，如果想放到别的地方，同样可以加上--out-file
参数:

```bash
syncrypto --decrypt-file [密文文件] --out-file [解密后文件]
```

### 修改密码

修改一个已经加密同步过后的密文目录中的密码

```bash
syncrypto --change-password [密文目录]
```
这条命令首先会提示输入当前密码，之后会提示设置新密码，设置成功后会将密文目录下的所有文件
重新加密一遍。


### 帮助

```bash
syncrypto -h
```


## License

Apache License, Version 2.0
