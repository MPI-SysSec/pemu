# Buffer overwrite in the SEmu f429 TCP Echo targets
## Summary
Both SEmu targets used for our evaluation contain buffer overflows. We believe this to be due to a configuration error.

## Detailed Description
The low-level buffer, where the raw network packets are written to is too small (`memp_memory_RX_POOL_base`). Therefore, if larger Ethernet frames (up to 1518 bytes) are written to the buffer they can overwrite the `netif` struct directly after the buffers. This struct contains function pointer which can be corrupted.

The sample is taken directly from the SEmu dataset. When trying to rebuild the sample we were unable to reproduce the faulty firmware. Therefore, we believe this to be due to a configuration error.

