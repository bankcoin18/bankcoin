# Dockerfile for building bank binaries.

Now, you can build your own bank files on all systems with docker and do it easy without installing depends on your system.

## How:

### Build docker image

```
sudo docker build .
```

### Run docker container

Builder will return HASH of image
Example:
Successfully built 9bbff825d50f

```
sudo docker run -it -v ~/path/to/bank/folder:/bank 9bbff825d50f
```

If your system uses SELINUX you may use --privileged=true key

```
sudo docker run --privileged=true -it -v ~/development/bank:/bank 9bbff825d50f
```

See bank-qt file in used bank folder and bankd file in src subfolder.