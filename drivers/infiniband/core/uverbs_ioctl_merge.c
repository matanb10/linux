/*
 * Copyright (c) 2016, Mellanox Technologies inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <rdma/uverbs_ioctl.h>
#include <linux/bitops.h>
#include "uverbs.h"

#define UVERBS_NUM_GROUPS (UVERBS_ID_RESERVED_MASK >> UVERBS_ID_RESERVED_SHIFT)

static const struct uverbs_type **get_next_type(const struct uverbs_type_group *types,
						const struct uverbs_type **type)
{
	while (type - types->types < types->num_types && !(*type))
		type++;

	return type - types->types < types->num_types ? type : NULL;
}

static const struct uverbs_action **get_next_action(const struct uverbs_action_group *group,
						    const struct uverbs_action **pcurr)
{
	while (pcurr - group->actions < group->num_actions && !(*pcurr))
		pcurr++;

	return pcurr - group->actions < group->num_actions ? pcurr : NULL;
}

static const struct uverbs_attr_spec *get_next_attr(const struct uverbs_attr_spec_group *group,
						    const struct uverbs_attr_spec *pcurr)
{
	while (pcurr - group->attrs < group->num_attrs && !pcurr->type)
		pcurr++;

	return pcurr - group->attrs < group->num_attrs ? pcurr : NULL;
}

static void _free_attr_spec_group(struct uverbs_attr_spec_group **attr_group,
				  unsigned int num_groups)
{
	unsigned int i;

	for (i = 0; i < num_groups; i++)
		kfree((void *)attr_group[i]);
}

static void free_attr_spec_group(struct uverbs_attr_spec_group **attr_group,
				 unsigned int num_groups)
{
	_free_attr_spec_group(attr_group, num_groups);
	kfree(attr_group);
}

static size_t get_attrs_from_trees(const struct uverbs_action **action_arr,
				   unsigned int elements,
				   struct uverbs_attr_spec_group ***out)
{
	unsigned int group_idx;
	struct uverbs_attr_spec_group *attr_spec_group[UVERBS_NUM_GROUPS];
	unsigned int max_action_specs = 0;
	unsigned int i;
	int ret;

	for (group_idx = 0; group_idx < UVERBS_NUM_GROUPS; group_idx++) {
		const struct uverbs_attr_spec_group *attr_group_trees[elements];
		unsigned int num_attr_group_trees = 0;
		const struct uverbs_attr_spec *attr_trees[elements];
		unsigned int num_attr_groups = 0;
		unsigned int attrs_in_group = 0;
		unsigned long *mandatory_attr_mask;

		for (i = 0; i < elements; i++) {
			const struct uverbs_action *action = action_arr[i];

			if (action->num_groups > group_idx &&
			    action->attr_groups[group_idx]) {
				const struct uverbs_attr_spec_group *spec_group =
					action->attr_groups[group_idx];

				attr_group_trees[num_attr_group_trees++] =
					spec_group;
				attr_trees[num_attr_groups++] =
					spec_group->attrs;
				if (spec_group->num_attrs > attrs_in_group)
					attrs_in_group = spec_group->num_attrs;
			}
		}

		if (!attrs_in_group) {
			attr_spec_group[group_idx] = NULL;
			continue;
		}

		attr_spec_group[group_idx] =
			kzalloc(sizeof(*attr_spec_group[group_idx]) +
				sizeof(struct uverbs_attr_spec) * attrs_in_group +
				sizeof(unsigned long) * BITS_TO_LONGS(attrs_in_group),
				GFP_KERNEL);
		if (!attr_spec_group[group_idx]) {
			ret = -ENOMEM;
			goto free_groups;
		}

		attr_spec_group[group_idx]->attrs =
			(void *)(attr_spec_group[group_idx] + 1);
		attr_spec_group[group_idx]->num_attrs = attrs_in_group;
		attr_spec_group[group_idx]->mandatory_attrs_bitmask =
			(void *)(attr_spec_group[group_idx]->attrs + attrs_in_group);
		mandatory_attr_mask =
			attr_spec_group[group_idx]->mandatory_attrs_bitmask;

		do {
			unsigned int tree_idx;
			bool found_next = false;
			unsigned int attr_trees_idx[num_attr_groups];
			unsigned int min_attr = INT_MAX;
			const struct uverbs_attr_spec *single_attr_trees[num_attr_groups];
			unsigned int num_single_attr_trees = 0;
			unsigned int num_attr_trees = 0;
			struct uverbs_attr_spec *allocated_attr;
			enum uverbs_attr_type cur_type = UVERBS_ATTR_TYPE_NA;
			unsigned int attr_type_idx = 0;

			for (tree_idx = 0; tree_idx < num_attr_group_trees;
			     tree_idx++) {
				const struct uverbs_attr_spec *next =
					get_next_attr(attr_group_trees[tree_idx],
						      attr_trees[tree_idx]);

				if (next) {
					found_next = true;
					attr_trees[num_attr_trees] = next;
					attr_trees_idx[num_attr_trees] =
						next - attr_group_trees[tree_idx]->attrs;
					if (min_attr > attr_trees_idx[num_attr_trees])
						min_attr = attr_trees_idx[num_attr_trees];
					num_attr_trees++;
				}
			}

			if (!found_next)
				break;

			max_action_specs = group_idx + 1;

			allocated_attr =
				attr_spec_group[group_idx]->attrs + min_attr;

			for (i = 0; i < num_attr_trees; i++) {
				if (attr_trees_idx[i] == min_attr) {
					single_attr_trees[num_single_attr_trees++] =
						attr_trees[i];
					attr_trees[i]++;
				}
			}

			for (i = 0; i < num_single_attr_trees; i++)
				switch (cur_type) {
				case UVERBS_ATTR_TYPE_NA:
					cur_type = single_attr_trees[i]->type;
					attr_type_idx = i;
					continue;
				case UVERBS_ATTR_TYPE_PTR_IN:
				case UVERBS_ATTR_TYPE_PTR_OUT:
				case UVERBS_ATTR_TYPE_IDR:
				case UVERBS_ATTR_TYPE_FD:
					if (single_attr_trees[i]->type !=
					    UVERBS_ATTR_TYPE_NA)
						WARN("%s\n", "uverbs_merge: Two types for the same attribute");
					break;
				case UVERBS_ATTR_TYPE_FLAG:
					if (single_attr_trees[i]->type !=
					    UVERBS_ATTR_TYPE_FLAG &&
					    single_attr_trees[i]->type !=
					    UVERBS_ATTR_TYPE_NA)
						WARN("%s\n", "uverbs_merge: Two types for the same attribute");
					break;
				default:
					WARN("%s\n", "uverbs_merge: Unknown attribute type given");
				}

			switch (cur_type) {
			case UVERBS_ATTR_TYPE_PTR_IN:
			case UVERBS_ATTR_TYPE_PTR_OUT:
			case UVERBS_ATTR_TYPE_IDR:
			case UVERBS_ATTR_TYPE_FD:
				/* PTR_IN and PTR_OUT can't be merged between trees */
				memcpy(allocated_attr,
				       single_attr_trees[attr_type_idx],
				       sizeof(*allocated_attr));
				break;
			case UVERBS_ATTR_TYPE_FLAG:
				allocated_attr->type =
					UVERBS_ATTR_TYPE_FLAG;
				allocated_attr->flags = 0;
				allocated_attr->flag.mask = 0;
				for (i = 0; i < num_single_attr_trees; i++) {
					allocated_attr->flags |=
						single_attr_trees[i]->flags;
					allocated_attr->flag.mask |=
						single_attr_trees[i]->flag.mask;
				}
				break;
			default:
				return -EINVAL;
			};

			if (allocated_attr->flags & UVERBS_ATTR_SPEC_F_MANDATORY)
				set_bit(min_attr, mandatory_attr_mask);
		} while (1);
	}

	*out = kcalloc(max_action_specs, sizeof(struct uverbs_attr_spec_group *),
		       GFP_KERNEL);
	if (!(*out))
		goto free_groups;

	for (group_idx = 0; group_idx < max_action_specs; group_idx++)
		(*out)[group_idx] = attr_spec_group[group_idx];

	return max_action_specs;

free_groups:
	_free_attr_spec_group(attr_spec_group, group_idx);

	return ret;
}

struct action_alloc_list {
	struct uverbs_action	action;
	unsigned int		action_idx;
	/* next is used in order to construct the group later on */
	struct list_head	list;
};

static void _free_type_actions_group(struct uverbs_action_group **action_groups,
				     unsigned int num_groups) {
	unsigned int i, j;

	for (i = 0; i < num_groups; i++) {
		if (!action_groups[i])
			continue;

		for (j = 0; j < action_groups[i]->num_actions; j++) {
			if (!action_groups[i]->actions[j]->attr_groups)
				continue;

			free_attr_spec_group((struct uverbs_attr_spec_group **)
					     action_groups[i]->actions[j]->attr_groups,
					     action_groups[i]->actions[j]->num_groups);
			kfree((void *)action_groups[i]->actions[j]);
		}
		kfree(action_groups[i]);
	}
}

static void free_type_actions_group(struct uverbs_action_group **action_groups,
				    unsigned int num_groups)
{
	_free_type_actions_group(action_groups, num_groups);
	kfree(action_groups);
}

static int get_actions_from_trees(const struct uverbs_type **type_arr,
				  unsigned int elements,
				  struct uverbs_action_group ***out)
{
	unsigned int group_idx;
	struct uverbs_action_group  *action_groups[UVERBS_NUM_GROUPS];
	unsigned int max_action_groups = 0;
	struct uverbs_action_group **allocated_type_actions_group = NULL;
	int i;

	for (group_idx = 0; group_idx < UVERBS_NUM_GROUPS; group_idx++) {
		const struct uverbs_action_group *actions_group_trees[elements];
		unsigned int num_actions_group_trees = 0;
		const struct uverbs_action **action_trees[elements];
		unsigned int num_action_trees = 0;
		unsigned int actions_in_group = 0;
		LIST_HEAD(allocated_group_list);

		for (i = 0; i < elements; i++) {
			if (type_arr[i]->num_groups > group_idx &&
			    type_arr[i]->action_groups[group_idx]) {
				actions_group_trees[num_actions_group_trees++] =
					type_arr[i]->action_groups[group_idx];
				action_trees[num_action_trees++] =
					type_arr[i]->action_groups[group_idx]->actions;
			}
		}

		do {
			unsigned int tree_idx;
			bool found_next = false;
			unsigned int action_trees_idx[num_action_trees];
			unsigned int min_action = INT_MAX;
			const struct uverbs_action *single_action_trees[num_action_trees];
			unsigned int num_single_action_trees = 0;
			unsigned int num_action_trees = 0;
			struct action_alloc_list *allocated_action = NULL;
			int ret;

			for (tree_idx = 0; tree_idx < num_actions_group_trees;
			     tree_idx++) {
				const struct uverbs_action **next =
					get_next_action(actions_group_trees[tree_idx],
							action_trees[tree_idx]);

				if (!next)
					continue;

				found_next = true;
				action_trees[num_action_trees] = next;
				action_trees_idx[num_action_trees] =
					next - actions_group_trees[tree_idx]->actions;
				if (min_action > action_trees_idx[num_action_trees])
					min_action = action_trees_idx[num_action_trees];
				num_action_trees++;
			}

			if (!found_next)
				break;

			for (i = 0; i < num_action_trees; i++) {
				if (action_trees_idx[i] == min_action) {
					single_action_trees[num_single_action_trees++] =
						*action_trees[i];
					action_trees[i]++;
				}
			}

			actions_in_group = min_action + 1;

			/* Now we have an array of all attributes of the same actions */
			allocated_action = kmalloc(sizeof(*allocated_action),
						   GFP_KERNEL);
			if (!allocated_action)
				goto free_list;

			/* Take the last tree which is parameter != NULL */
			for (i = num_single_action_trees - 1;
			     i >= 0 && !single_action_trees[i]->handler; i--)
				;
			if (WARN_ON(i < 0)) {
				allocated_action->action.flags = 0;
				allocated_action->action.handler = NULL;
			} else {
				allocated_action->action.flags =
					single_action_trees[i]->flags;
				allocated_action->action.handler =
					single_action_trees[i]->handler;
			}
			allocated_action->action.num_child_attrs = 0;

			ret = get_attrs_from_trees(single_action_trees,
						   num_single_action_trees,
						   (struct uverbs_attr_spec_group ***)
						   &allocated_action->action.attr_groups);
			if (ret < 0) {
				kfree(allocated_action);
				goto free_list;
			}

			allocated_action->action.num_groups = ret;

			for (i = 0; i < allocated_action->action.num_groups;
			     allocated_action->action.num_child_attrs +=
				allocated_action->action.attr_groups[i]->num_attrs, i++)
				;

			allocated_action->action_idx = min_action;
			list_add_tail(&allocated_action->list,
				      &allocated_group_list);
		} while (1);

		if (!actions_in_group) {
			action_groups[group_idx] = NULL;
			continue;
		}

		action_groups[group_idx] =
			kmalloc(sizeof(*action_groups[group_idx]) +
				sizeof(struct uverbs_action *) * actions_in_group,
				GFP_KERNEL);

		if (!action_groups[group_idx])
			goto free_list;

		action_groups[group_idx]->num_actions = actions_in_group;
		action_groups[group_idx]->actions =
			(void *)(action_groups[group_idx] + 1);
		{
			struct action_alloc_list *iter;

			list_for_each_entry(iter, &allocated_group_list, list)
				action_groups[group_idx]->actions[iter->action_idx] =
					(const struct uverbs_action *)&iter->action;
		}

		max_action_groups = group_idx + 1;

		continue;

free_list:
		{
			struct action_alloc_list *iter, *tmp;

			list_for_each_entry_safe(iter, tmp,
						 &allocated_group_list, list)
				kfree(iter);

			goto free_groups;
		}
	}

	allocated_type_actions_group =
		kmalloc(sizeof(*allocated_type_actions_group) * max_action_groups,
			GFP_KERNEL);
	if (!allocated_type_actions_group)
		goto free_groups;

	memcpy(allocated_type_actions_group, action_groups,
	       sizeof(*allocated_type_actions_group) * max_action_groups);

	*out = allocated_type_actions_group;

	return max_action_groups;

free_groups:
	_free_type_actions_group(action_groups, max_action_groups);

	return -ENOMEM;
}

struct type_alloc_list {
	struct uverbs_type	type;
	unsigned int		type_idx;
	/* next is used in order to construct the group later on */
	struct list_head	list;
};

static void _free_types(struct uverbs_type_group **types, unsigned int num_types)
{
	unsigned int i, j;

	for (i = 0; i < num_types; i++) {
		if (!types[i])
			continue;

		for (j = 0; j < types[i]->num_types; j++) {
			if (!types[i]->types[j])
				continue;

			free_type_actions_group((struct uverbs_action_group **)
						types[i]->types[j]->action_groups,
						types[i]->types[j]->num_groups);
			kfree((void *)types[i]->types[j]);
		}
		kfree(types[i]);
	}
}

struct uverbs_root *uverbs_alloc_spec_tree(unsigned int num_trees,
					   const struct uverbs_root_spec *trees)
{
	unsigned int group_idx;
	struct uverbs_type_group *types_groups[UVERBS_NUM_GROUPS];
	unsigned int max_types_groups = 0;
	struct uverbs_root *allocated_types_group = NULL;
	int i;

	memset(types_groups, 0, sizeof(*types_groups));

	for (group_idx = 0; group_idx < UVERBS_NUM_GROUPS; group_idx++) {
		const struct uverbs_type **type_trees[num_trees];
		unsigned int types_in_group = 0;
		LIST_HEAD(allocated_group_list);

		for (i = 0; i < num_trees; i++)
			type_trees[i] = trees[i].types->types;

		do {
			const struct uverbs_type *curr_type[num_trees];
			unsigned int type_trees_idx[num_trees];
			unsigned int trees_for_curr_type = 0;
			unsigned int min_type = INT_MAX;
			unsigned int num_type_trees = 0;
			bool found_next = false;
			unsigned int tree_idx;
			int res;
			struct type_alloc_list *allocated_type = NULL;

			for (tree_idx = 0; tree_idx < num_trees; tree_idx++) {
				if (trees[tree_idx].group_id == group_idx) {
					const struct uverbs_type **next =
						get_next_type(trees[tree_idx].types,
							      type_trees[tree_idx]);

					if (!next)
						continue;

					found_next = true;
					type_trees[num_type_trees] = next;
					type_trees_idx[num_type_trees] =
						next - trees[tree_idx].types->types;
					if (min_type > type_trees_idx[num_type_trees])
						min_type = type_trees_idx[num_type_trees];
					num_type_trees++;
				}
			}

			if (!found_next)
				break;

			max_types_groups = group_idx + 1;

			for (i = 0; i < num_type_trees; i++)
				/*
				 * We must have at least one hit here,
				 * as we found this min type
				 */
				if (type_trees_idx[i] == min_type) {
					curr_type[trees_for_curr_type++] =
						*type_trees[i];
					type_trees[i]++;
				}

			types_in_group = min_type + 1;

			/*
			 * Do things for type:
			 * 1. Get action_groups and num_group.
			 * 2. Allocate uverbs_type. Copy alloc pointer
			 *      (shallow copy) and fill in num_groups and
			 *      action_groups.
			 *      In order to hash them, allocate a struct of
			 *      {uverbs_type, list_head}
			 * 3. Put that pointer in types_group[group_idx].
			 */
			allocated_type = kmalloc(sizeof(*allocated_type),
						 GFP_KERNEL);
			if (!allocated_type)
				goto free_list;

			/* Take the last tree which is parameter != NULL */
			for (i = trees_for_curr_type - 1;
			     i >= 0 && !curr_type[i]->alloc; i--)
				;
			if (i < 0)
				allocated_type->type.alloc = NULL;
			else
				allocated_type->type.alloc = curr_type[i]->alloc;

			res = get_actions_from_trees(curr_type,
						     trees_for_curr_type,
						     (struct uverbs_action_group ***)
						     &allocated_type->type.action_groups);
			if (res < 0) {
				kfree(allocated_type);
				goto free_list;
			}

			allocated_type->type.num_groups = res;
			allocated_type->type_idx = min_type;
			list_add_tail(&allocated_type->list,
				      &allocated_group_list);
		} while (1);

		if (!types_in_group) {
			types_groups[group_idx] = NULL;
			continue;
		}

		types_groups[group_idx] = kzalloc(sizeof(*types_groups[group_idx]) +
						  sizeof(struct uverbs_type *) * types_in_group,
						  GFP_KERNEL);
		if (!types_groups[group_idx])
			goto free_list;

		types_groups[group_idx]->num_types = types_in_group;
		types_groups[group_idx]->types =
			(void *)(types_groups[group_idx] + 1);
		{
			struct type_alloc_list *iter;

			list_for_each_entry(iter, &allocated_group_list, list)
				types_groups[group_idx]->types[iter->type_idx] =
					(const struct uverbs_type *)&iter->type;
		}

		continue;

free_list:
		{
			struct type_alloc_list *iter, *tmp;

			list_for_each_entry_safe(iter, tmp,
						 &allocated_group_list, list)
				kfree(iter);

			goto free_groups;
		}
	}

	/*
	 * 1. Allocate struct uverbs_root + space for type_groups array.
	 * 2. Fill it with types_group
	 *	memcpy(allocated_space + 1, types_group,
	 *	       sizeof(types_group[0]) * max_types_groups)
	 * 3. If anything fails goto free_groups;
	 */
	allocated_types_group =
		kmalloc(sizeof(*allocated_types_group) +
			sizeof(*allocated_types_group->type_groups) * max_types_groups,
			GFP_KERNEL);
	if (!allocated_types_group)
		goto free_groups;

	allocated_types_group->type_groups = (void *)(allocated_types_group + 1);
	memcpy(allocated_types_group->type_groups, types_groups,
	       sizeof(*allocated_types_group->type_groups) * max_types_groups);
	allocated_types_group->num_groups = max_types_groups;

	return allocated_types_group;

free_groups:
	_free_types(types_groups, max_types_groups);

	return ERR_PTR(-ENOMEM);
}
EXPORT_SYMBOL(uverbs_alloc_spec_tree);

void uverbs_specs_free(struct uverbs_root *root)
{
	_free_types((struct uverbs_type_group **)root->type_groups,
		    root->num_groups);
	kfree(root);
}
EXPORT_SYMBOL(uverbs_specs_free);

