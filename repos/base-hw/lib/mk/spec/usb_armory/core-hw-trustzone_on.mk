#
# \brief  Build config for parts of core that depend on Trustzone status
# \author Martin Stein
# \date   2015-10-30
#

# add include paths
INC_DIR += $(REP_DIR)/src/core/include/spec/usb_armory

# include less specific configuration
include $(REP_DIR)/lib/mk/spec/imx53/core-hw-trustzone_on.inc
