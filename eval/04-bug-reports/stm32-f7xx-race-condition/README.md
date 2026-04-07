# Race condition in the STM32 F7xx network stack
## Summary

Potential arbitrary pointer dereference due to a race condition in the ethernet `low_level_output` function of the [LwIP_HTTP_Server_Netconn_RTOS](https://github.com/STMicroelectronics/STM32CubeF7/tree/master/Projects/STM32F767ZI-Nucleo/Applications/LwIP/LwIP_HTTP_Server_Netconn_RTOS) application, built with STM32CubeF7, for the STM32F767ZI-Nucleo MCU.

---

## Detailed description

For all STM32F7xx application samples that use the LwIP network stack (at least to out knowledge), the function [`low_level_output`](https://github.com/STMicroelectronics/STM32CubeF7/blob/043a9bf77465a9442127aac7307fdb36c9d47a36/Projects/STM32F769I_EVAL/Applications/LwIP/LwIP_IAP/Src/ethernetif.c#L205), which is called by the LwIP function `ethernet_output` handles the transmission of ethernet frames.  

`low_level_output` uses the global variable `TxConfig` to prepare the transmission of data and then calls the HAL function `HAL_ETH_transmit`.  
[source code of low_level_input:](https://github.com/STMicroelectronics/STM32CubeF7/blob/043a9bf77465a9442127aac7307fdb36c9d47a36/Projects/STM32F769I_EVAL/Applications/LwIP/LwIP_IAP/Src/ethernetif.c#L235C2-L239C69)
```
  TxConfig.Length = p->tot_len;
  TxConfig.TxBuffer = Txbuffer;
  TxConfig.pData = p;

  pbuf_ref(p);
  // potential race condition
  do
  {
    if(HAL_ETH_Transmit_IT(&EthHandle, &TxConfig) == HAL_OK)
    {
      errval = ERR_OK;
    }
```

However, the access to this global variable is not synchronized. Hence, if the thread is re-scheduled after configuring `TxConfig` and before calling the `HAL_ETH_Transmit_IT` (in stm32f7xx_hal_eth.c), the global variable can be overwritten, if another thread tries to send a frame as well.  

This can be the case when, for example, the first thread is trying to send a scheduled ARP packet, and the  second thread tries to send a response to a packet the firmware received while preparing the transmission of the ARP packet.

The second thread also calls `low_level_output`, overwrites the `Length, TxBuffer, and pData` fields of the global `TxConfig` and transmits its frame.  
`TxBuffer` points to a linked list of buffer descriptors, that contain the length, the buffer address, and a pointer the next linked list item (see below). This linked list is part of `low_level_outputs` stack frame.

When the second thread returns from the `low_level_output` function the stack space is reclaimed and the stored `TxBuffer` list is overwritten.  

Once the execution returns to the first thread (i.e., the first incocation of `low_level_outout`), the data that `TxConfig.TxBuffer` points to is most likely corrupted.  

One implication can occur when `low_level_output` then calls `HAL_ETH_Transmit_IT` (in stm32f7xx_hal_eth.c), which in turn calls `ETH_Prepare_Tx_Descriptor` (in stm32f7xx_hal_eth.c) to prepare the Tx DMA descriptor(s) before the transmission. For this purpose it iterates over the (corrupted) `TxBuffer` list, and dereferences the `next` pointer of the current `TxBuffer` item. As the entire linked list item was likely overwritten, the value of the `next` pointer is corrupted and dereferencing it leads to undefined behavior.

Depending, on the current state of the second thread's stack frame, this may have other possible consequences.  


```
  /**
    * @brief  ETH Buffers List structure definition
    */
  typedef struct __ETH_BufferTypeDef
  {
    uint8_t *buffer;                /*<! buffer address */
  
    uint32_t len;                   /*<! buffer length */
  
    struct __ETH_BufferTypeDef *next; /*<! Pointer to the next buffer in the list */
  } ETH_BufferTypeDef;
```

---

## Impact
As out-of-bounds memory potentially gets corrupted with user-supplied data, this could lead to data being leaked via Ethernet, when a malicious user is able to replicate malicious `TxBuffer` structs, whoose buffer pointer points to data that should be leaked.  

---

## Further affected targets

We discovered the bug in the [LwIP_HTTP_Server_Netconn_RTOS](https://github.com/STMicroelectronics/STM32CubeF7/tree/master/Projects/STM32F767ZI-Nucleo/Applications/LwIP/LwIP_HTTP_Server_Netconn_RTOS) application. From our manual code analysis we assume this bug to be present other applications of STM32CubeF7 as.

Furthermore, this bug might also be present in other MCU packages as well (e.g., [STM32CubeF4](https://github.com/STMicroelectronics/STM32CubeF4/blob/master/Projects/STM32F429ZI-Nucleo/Applications/LwIP/LwIP_HTTP_Server_Netconn_RTOS/Src/ethernetif.c))

---

