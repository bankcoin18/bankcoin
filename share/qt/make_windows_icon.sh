#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/bank.ico

convert ../../src/qt/res/icons/bank-16.png ../../src/qt/res/icons/bank-32.png ../../src/qt/res/icons/bank-48.png ${ICON_DST}
