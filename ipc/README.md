# IPC Service standalone example

This example extracts `ipcservice.c` from the Nt sources into a minimal standalone project.

The example focuses on demonstrating how to build the file outside of the full Nt tree. The standalone build uses stub
implementations that keep the public API shape but do not start a real IPC service.

## Build

```sh
make
```

## Run

```sh
./ipcservice_example
```

The executable initialises the IPC environment using `/tmp` as the base directory and exits.
