#!/usr/bin/env python3
# noqa
"""Random magic for the Playdate"""
import os
import subprocess

from time import sleep
from typing import List
from typing import NamedTuple

PLAYDATE_RAM_START = 0x20000000
PLAYDATE_RAM_END = 0x20050000
PLAYDATE_MEM_START = 0x08000000
PLAYDATE_MEM_END = 0x08100000
PLAYDATE_USER_START = 0x08050000
PLAYDATE_USER_END = 0x08100000
PLAYDATE_KERNEL_START = 0x08000000
PLAYDATE_KERNEL_END = 0x08050000

PLAYDATE_RAM_SIZE = PLAYDATE_RAM_END - PLAYDATE_RAM_START
PLAYDATE_KERNEL_SIZE = PLAYDATE_KERNEL_END - PLAYDATE_KERNEL_START
PLAYDATE_USER_SIZE = PLAYDATE_USER_END - PLAYDATE_USER_START
PLAYDATE_MEM_SIZE = PLAYDATE_MEM_END - PLAYDATE_MEM_START

PLAYDATE_ROUGH_USER_END = 0x080E0000
# "educated guesstimation"
PLAYDATE_ROUGH_USER_SIZE = PLAYDATE_ROUGH_USER_END - PLAYDATE_USER_START

# Token Search Magic Items
PLAYDATE_USER_DATA_SEARCH_START = 0x60000
# these were chosen at random bc they probably won't change. hopefully they don't start yolo matching on other stuff
USER_TOKEN_LIST: List[bytes] = [b"playdate.system." +
                                x for x in [b"game", b"updateGameList", b"getInstalledGameList"]]
KERNEL_TOKEN_LIST: List[bytes] = [b"/pdfw", b"Firmware image is too big! 960K max.",
                                  b"1:journal.jnl", b"/crashlog.txt\x00--- forced reset \x00--- watchdog reset "]

PD_HEADER_FLAGS = {
    "defines": ["-D__FPU_USED=1", "-DTARGET_EXTENSION=1", "-DTARGET_PLAYDATE"],
    "flags": ["-mthumb", "-mcpu=cortex-m7", "-mfloat-abi=hard", "-mfpu=fpv5-sp-d16", "-fomit-frame-pointer", "-falign-functions=16"],
}


def get_system_headers():
    output = subprocess.getoutput("clang -Wp,-v -E -")

    line = ""
    c = 0
    output = output.splitlines()

    while "#include <...> search starts here:" not in line:
        line = output[c]
        c += 1
    c += 1

    # the next lines are the header paths we want
    lines: List[str] = []
    while "End of search list." not in line:
        lines.append(line)
        line = output[c]
        c += 1

    return lines


IVT_LEN = 0x1C8
IVT_ELEMENTS = IVT_LEN // 4


STM32F7_IVT_NAMES = [
    "SP_VALUE",
    "RESET_IRQ",
    "NMI_IRQ",
    "HARDFAULT_IRQ",
    "MEMORYMANAGE_IRQ",
    "BUSFAULT_IRQ",
    "USAGEFAULT_IRQ",
    "RESERVED",
    "RESERVED",
    "RESERVED",
    "RESERVED",
    "SVCALL_IRQ",
    "DEBUG_MONITOR_IRQ",
    "RESERVED",
    "PEND_SV_IRQ",
    "SYSTICK_IRQ",
    "NVIC_WWDG_IRQ",
    "NVIC_PVD_IRQ",
    "NVIC_TAMP_STAMP_IRQ",
    "NVIC_RTC_WKUP_IRQ",
    "NVIC_FLASH_IRQ",
    "NVIC_RCC_IRQ",
    "NVIC_EXTI0_IRQ",
    "NVIC_EXTI1_IRQ",
    "NVIC_EXTI2_IRQ",
    "NVIC_EXTI3_IRQ",
    "NVIC_EXTI4_IRQ",
    "NVIC_DMA1_STREAM0_IRQ",
    "NVIC_DMA1_STREAM1_IRQ",
    "NVIC_DMA1_STREAM2_IRQ",
    "NVIC_DMA1_STREAM3_IRQ",
    "NVIC_DMA1_STREAM4_IRQ",
    "NVIC_DMA1_STREAM5_IRQ",
    "NVIC_DMA1_STREAM6_IRQ",
    "NVIC_ADC_IRQ",
    "NVIC_CAN1_TX_IRQ",
    "NVIC_CAN1_RX0_IRQ",
    "NVIC_CAN1_RX1_IRQ",
    "NVIC_CAN1_SCE_IRQ",
    "NVIC_EXTI9_5_IRQ",
    "NVIC_TIM1_BRK_TIM9_IRQ",
    "NVIC_TIM1_UP_TIM10_IRQ",
    "NVIC_TIM1_TRG_COM_TIM11_IRQ",
    "NVIC_TIM1_CC_IRQ",
    "NVIC_TIM2_IRQ",
    "NVIC_TIM3_IRQ",
    "NVIC_TIM4_IRQ",
    "NVIC_I2C1_EV_IRQ",
    "NVIC_I2C1_ER_IRQ",
    "NVIC_I2C2_EV_IRQ",
    "NVIC_I2C2_ER_IRQ",
    "NVIC_SPI1_IRQ",
    "NVIC_SPI2_IRQ",
    "NVIC_USART1_IRQ",
    "NVIC_USART2_IRQ",
    "NVIC_USART3_IRQ",
    "NVIC_EXTI15_10_IRQ",
    "NVIC_RTC_ALARM_IRQ",
    "NVIC_USB_FS_WKUP_IRQ",
    "NVIC_TIM8_BRK_TIM12_IRQ",
    "NVIC_TIM8_UP_TIM13_IRQ",
    "NVIC_TIM8_TRG_COM_TIM14_IRQ",
    "NVIC_TIM8_CC_IRQ",
    "NVIC_DMA1_STREAM7_IRQ",
    "NVIC_FSMC_IRQ",
    "NVIC_SDMMC1_IRQ",
    "NVIC_TIM5_IRQ",
    "NVIC_SPI3_IRQ",
    "NVIC_UART4_IRQ",
    "NVIC_UART5_IRQ",
    "NVIC_TIM6_DAC_IRQ",
    "NVIC_TIM7_IRQ",
    "NVIC_DMA2_STREAM0_IRQ",
    "NVIC_DMA2_STREAM1_IRQ",
    "NVIC_DMA2_STREAM2_IRQ",
    "NVIC_DMA2_STREAM3_IRQ",
    "NVIC_DMA2_STREAM4_IRQ",
    "NVIC_ETH_IRQ",
    "NVIC_ETH_WKUP_IRQ",
    "NVIC_CAN2_TX_IRQ",
    "NVIC_CAN2_RX0_IRQ",
    "NVIC_CAN2_RX1_IRQ",
    "NVIC_CAN2_SCE_IRQ",
    "NVIC_OTG_FS_IRQ",
    "NVIC_DMA2_STREAM5_IRQ",
    "NVIC_DMA2_STREAM6_IRQ",
    "NVIC_DMA2_STREAM7_IRQ",
    "NVIC_USART6_IRQ",
    "NVIC_I2C3_EV_IRQ",
    "NVIC_I2C3_ER_IRQ",
    "NVIC_OTG_HS_EP1_OUT_IRQ",
    "NVIC_OTG_HS_EP1_IN_IRQ",
    "NVIC_OTG_HS_WKUP_IRQ",
    "NVIC_OTG_HS_IRQ",
    "NVIC_DCMI_IRQ",
    "NVIC_CRYP_IRQ",
    "NVIC_HASH_RNG_IRQ",
    "NVIC_FPU_IRQ",
    "NVIC_UART7_IRQ",
    "NVIC_UART8_IRQ",
    "NVIC_SPI4_IRQ",
    "NVIC_SPI5_IRQ",
    "NVIC_SPI6_IRQ",
    "NVIC_SAI1_IRQ",
    "NVIC_LCD_TFT_IRQ",
    "NVIC_LCD_TFT_ERR_IRQ",
    "NVIC_DMA2D_IRQ",
    "NVIC_SAI2_IRQ",
    "NVIC_QUADSPI_IRQ",
    "NVIC_LP_TIMER_1_IRQ",
    "NVIC_HDMI_CEC_IRQ",
    "NVIC_I2C4_EV_IRQ",
    "NVIC_I2C4_ER_IRQ",
    "NVIC_SPDIFRX_IRQ",
]


class SRAM_REGION(NamedTuple):
    name: str
    start: int
    end: int


STM32F7_SRAM_REGIONS: List[SRAM_REGION] = [
    SRAM_REGION("DTCM", 0x20000000, 0x20010000),
    SRAM_REGION("SRAM1", 0x20010000, 0x2004C000),
    SRAM_REGION("SRAM2", 0x2004C000, 0x20050000)
]

# import require binaryninja api beyond this point

try:
    from binaryninja import *
    binary_ninja_present = True
except ImportError:
    binary_ninja_present = False

if binary_ninja_present:
    from .pd_types import make_stable_library  # noqa
    from .pd_types import make_yolo_library  # noqa
