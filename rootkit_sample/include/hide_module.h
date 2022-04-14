#ifndef BSO_ROOTKIT_HIDE_MODULE_H
#define BSO_ROOTKIT_HIDE_MODULE_H

#include "utils.h"

extern short visiblity;
extern struct list_head *prev_module;

void hide_rootkit(void);

void show_rootkit(void);

#endif //BSO_ROOTKIT_HIDE_MODULE_H
