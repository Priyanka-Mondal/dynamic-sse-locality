#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux
CND_DLIB_EXT=so
CND_CONF=Release
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/AES.o \
	${OBJECTDIR}/AVLTree.o \
	${OBJECTDIR}/Amortized.o \
	${OBJECTDIR}/AmortizedBASClient.o \
	${OBJECTDIR}/AmortizedBASServer.o \
	${OBJECTDIR}/Bid.o \
	${OBJECTDIR}/OMAP.o \
	${OBJECTDIR}/ORAM.o \
	${OBJECTDIR}/OneChoiceClient.o \
	${OBJECTDIR}/OneChoiceServer.o \
	${OBJECTDIR}/OneChoiceStorage.o \
	${OBJECTDIR}/RAMStore.o \
	${OBJECTDIR}/Server.o \
	${OBJECTDIR}/Storage.o \
	${OBJECTDIR}/TwoChoicePPwithStashClient.o \
	${OBJECTDIR}/TwoChoicePPwithStashServer.o \
	${OBJECTDIR}/TwoChoicePPwithStashStorage.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o \
	${OBJECTDIR}/Utilities.o \
	${OBJECTDIR}/logger.o \
	${OBJECTDIR}/main.o \
	${OBJECTDIR}/utils.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/sse-locality-sda

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/sse-locality-sda: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/sse-locality-sda ${OBJECTFILES} ${LDLIBSOPTIONS}

${OBJECTDIR}/AES.o: AES.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AES.o AES.cpp

${OBJECTDIR}/AVLTree.o: AVLTree.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AVLTree.o AVLTree.cpp

${OBJECTDIR}/Amortized.o: Amortized.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Amortized.o Amortized.cpp

${OBJECTDIR}/AmortizedBASClient.o: AmortizedBASClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedBASClient.o AmortizedBASClient.cpp

${OBJECTDIR}/AmortizedBASServer.o: AmortizedBASServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedBASServer.o AmortizedBASServer.cpp

${OBJECTDIR}/Bid.o: Bid.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Bid.o Bid.cpp

${OBJECTDIR}/OMAP.o: OMAP.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OMAP.o OMAP.cpp

${OBJECTDIR}/ORAM.o: ORAM.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/ORAM.o ORAM.cpp

${OBJECTDIR}/OneChoiceClient.o: OneChoiceClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceClient.o OneChoiceClient.cpp

${OBJECTDIR}/OneChoiceServer.o: OneChoiceServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceServer.o OneChoiceServer.cpp

${OBJECTDIR}/OneChoiceStorage.o: OneChoiceStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceStorage.o OneChoiceStorage.cpp

${OBJECTDIR}/RAMStore.o: RAMStore.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/RAMStore.o RAMStore.cpp

${OBJECTDIR}/Server.o: Server.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Server.o Server.cpp

${OBJECTDIR}/Storage.o: Storage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Storage.o Storage.cpp

${OBJECTDIR}/TwoChoicePPwithStashClient.o: TwoChoicePPwithStashClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPwithStashClient.o TwoChoicePPwithStashClient.cpp

${OBJECTDIR}/TwoChoicePPwithStashServer.o: TwoChoicePPwithStashServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPwithStashServer.o TwoChoicePPwithStashServer.cpp

${OBJECTDIR}/TwoChoicePPwithStashStorage.o: TwoChoicePPwithStashStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPwithStashStorage.o TwoChoicePPwithStashStorage.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o: TwoChoiceWithOneChoiceClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o TwoChoiceWithOneChoiceClient.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o: TwoChoiceWithOneChoiceServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o TwoChoiceWithOneChoiceServer.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o: TwoChoiceWithOneChoiceStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o TwoChoiceWithOneChoiceStorage.cpp

${OBJECTDIR}/Utilities.o: Utilities.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Utilities.o Utilities.cpp

${OBJECTDIR}/logger.o: logger.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/logger.o logger.cpp

${OBJECTDIR}/main.o: main.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/main.o main.cpp

${OBJECTDIR}/utils.o: utils.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/utils.o utils.cpp

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
