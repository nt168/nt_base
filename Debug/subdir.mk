################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../common.c \
../fatal.c \
../nt_base.c \
../nt_log.c \
../nt_mutexs.c \
../nt_phreads.c 

C_DEPS += \
./common.d \
./fatal.d \
./nt_base.d \
./nt_log.d \
./nt_mutexs.d \
./nt_phreads.d 

OBJS += \
./common.o \
./fatal.o \
./nt_base.o \
./nt_log.o \
./nt_mutexs.o \
./nt_phreads.o 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean--2e-

clean--2e-:
	-$(RM) ./common.d ./common.o ./fatal.d ./fatal.o ./nt_base.d ./nt_base.o ./nt_log.d ./nt_log.o ./nt_mutexs.d ./nt_mutexs.o ./nt_phreads.d ./nt_phreads.o

.PHONY: clean--2e-

