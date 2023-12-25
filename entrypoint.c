#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "http.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivanov Ivan");
MODULE_VERSION("0.01");

struct inode *networkfs_get_inode(struct super_block *sb,
                                  const struct inode *parent, umode_t mode,
                                  int i_ino);
int networkfs_fill_super(struct super_block *sb, struct fs_context *fc);
int networkfs_get_tree(struct fs_context *fc);
int networkfs_init_fs_context(struct fs_context *fc);
void networkfs_kill_sb(struct super_block *sb);
int networkfs_iterate(struct file *filp, struct dir_context *ctx);
struct dentry *networkfs_lookup(struct inode *parent, struct dentry *child,
                                unsigned int flag);
int networkfs_unlink(struct inode *parent, struct dentry *child);
int networkfs_create(struct user_namespace *user_ns, struct inode *parent,
                     struct dentry *child, umode_t mode, bool b);
int networkfs_mkdir(struct user_namespace *user_ns, struct inode *parent,
                    struct dentry *child, umode_t mode);
int networkfs_rmdir(struct inode *parent, struct dentry *child);

char *get_token(struct inode *inode) { return (char *)inode->i_sb->s_fs_info; }

struct entries {
  size_t entries_count;
  struct entry {
    unsigned char entry_type;  // DT_DIR (4) or DT_REG (8)
    ino_t ino;
    char name[256];
  } entries[16];
};

struct entry_info {
  unsigned char entry_type;  // DT_DIR (4) or DT_REG (8)
  ino_t ino;
};

struct file_operations networkfs_dir_ops = {
    .iterate = networkfs_iterate,
};
struct file_system_type networkfs_fs_type = {
    .name = "networkfs",
    .init_fs_context = networkfs_init_fs_context,
    .kill_sb = networkfs_kill_sb};

struct fs_context_operations networkfs_context_ops = {.get_tree =
                                                          networkfs_get_tree};

struct inode_operations networkfs_inode_ops = {.lookup = networkfs_lookup,
                                               .create = networkfs_create,
                                               .unlink = networkfs_unlink,
                                               .mkdir = networkfs_mkdir,
                                               .rmdir = networkfs_rmdir};

int networkfs_init(void) {
  int register_status = register_filesystem(&networkfs_fs_type);
  if (register_status) {
    return register_status;
  }
  return 0;
}

void networkfs_exit(void) {
  int unregister_status = unregister_filesystem(&networkfs_fs_type);
  if (unregister_status) {
    printk(KERN_ERR "Couldn't unregister networkfs filesystem");
  }
}

int networkfs_init_fs_context(struct fs_context *fc) {
  fc->ops = &networkfs_context_ops;
  printk(KERN_INFO "networkfs_init_fs_context\n");  // debug
  return 0;
}

void networkfs_kill_sb(struct super_block *sb) {
  printk(KERN_INFO "networkfs: superblock is destroyed");
  printk(KERN_INFO "networkfs: token = %s\n", (char *)(sb->s_fs_info));
  kfree((char *)(sb->s_fs_info));
}

/**
 * @sb:     Суперблок файловой системы.
 * @parent: Родительская inode (NULL для корня ФС).
 * @mode:   Битовая маска из прав доступа и типа файла:
 * https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/stat.h#L9.
 * @i_ino:  Уникальный идентификатор inode.
 */
struct inode *networkfs_get_inode(struct super_block *sb,
                                  const struct inode *parent, umode_t mode,
                                  int i_ino) {
  struct inode *inode;
  inode = new_inode(sb);

  if (inode != NULL) {
    inode->i_ino = i_ino;
    inode_init_owner(&init_user_ns, inode, parent, mode);
    inode->i_op = &networkfs_inode_ops;
    inode->i_fop = &networkfs_dir_ops;
  }

  return inode;
}

int networkfs_fill_super(struct super_block *sb, struct fs_context *fc) {
  // Создаём корневую inode
  struct inode *inode = networkfs_get_inode(
      sb, NULL, S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO, 1000);
  // Создаём корень файловой системы
  sb->s_root = d_make_root(inode);

  if (sb->s_root == NULL) {
    return -ENOMEM;
  }

  int num_bytes = strlen(fc->source) + 1;
  char *token = kmalloc(num_bytes, GFP_KERNEL);
  if (token == NULL) {
    printk(KERN_ERR "networkfs: unable to allocate memory for token");
    return -ENOMEM;
  }
  memcpy(token, fc->source, num_bytes);
  sb->s_fs_info = token;

  return 0;
}

int networkfs_get_tree(struct fs_context *fc) {
  int ret = get_tree_nodev(fc, networkfs_fill_super);

  if (ret != 0) {
    printk(KERN_ERR "networkfs: unable to mount: error code %d", ret);
  }

  return ret;
}

struct dentry *networkfs_lookup(struct inode *parent, struct dentry *child,
                                unsigned int flag) {
  const char *name = child->d_name.name;
  if (child->d_name.len > 255) {
    printk(KERN_ERR "networkfs lookup: name length is greater than 255");
    return NULL;
  }
  char ino_as_string[22];
  sprintf(ino_as_string, "%lu", parent->i_ino);

  size_t response_buffer_size = sizeof(struct entry_info);
  char *response_buffer = kmalloc(response_buffer_size, GFP_KERNEL);
  if (!response_buffer) {
    printk(KERN_ERR
           "networkfs lookup: could not allocate memory for response buffer");
    return NULL;
  }
  int response_status = networkfs_http_call(
      get_token(parent), "lookup", response_buffer, response_buffer_size, 2,
      "parent", ino_as_string, "name", name);
  if (response_status) {
    printk(KERN_ERR
           "networkfs lookup: HTTP request has failed: response status %d\n",
           response_status);
    return NULL;
  }

  struct entry_info *my_entry_info_struct =
      (struct entry_info *)response_buffer;

  struct inode *inode = networkfs_get_inode(
      parent->i_sb, parent,
      (my_entry_info_struct->entry_type == DT_DIR ? S_IFDIR : S_IFREG) |
          S_IRWXU | S_IRWXG | S_IRWXO,
      my_entry_info_struct->ino);

  d_add(child, inode);

  return NULL;
}

int networkfs_helper_get_list(struct inode *inode, struct entries **entries) {
  size_t response_buffer_size = sizeof(struct entries);
  char *response_buffer = kmalloc(response_buffer_size, GFP_KERNEL);
  if (!response_buffer) {
    printk(KERN_ERR
           "networkfs list: could not allocate memory for response buffer");
    return -1;
  }

  char ino_as_string[22];
  sprintf(ino_as_string, "%lu", inode->i_ino);

  int response_status =
      networkfs_http_call(get_token(inode), "list", response_buffer,
                          response_buffer_size, 1, "inode", ino_as_string);
  if (response_status) {
    printk(KERN_ERR
           "networkfs list: HTTP request has failed: response status %d\n",
           response_status);
    return response_status;
  }

  *entries = (struct entries *)response_buffer;
  return 0;
}

int networkfs_iterate(struct file *filp, struct dir_context *ctx) {
  struct dentry *dentry = filp->f_path.dentry;
  struct inode *inode = dentry->d_inode;

  struct entries *my_entries_struct = NULL;
  networkfs_helper_get_list(inode, &my_entries_struct);

  printk(KERN_DEBUG "networkfs iterate: before loop ctx->pos %lld\n", ctx->pos);

  loff_t record_counter = 0;

  for (; ctx->pos < my_entries_struct->entries_count;
       ++ctx->pos, ++record_counter) {
    char *entry_name = my_entries_struct->entries[ctx->pos].name;
    printk(KERN_DEBUG "networkfs iterate: entry name = %s\n", entry_name);

    dir_emit(ctx, entry_name, strlen(entry_name),
             my_entries_struct->entries[ctx->pos].ino,
             my_entries_struct->entries[ctx->pos].entry_type);
  }
  printk(KERN_DEBUG "networkfs iterate: record counter %lld\n", record_counter);

  kfree(my_entries_struct);
  return record_counter;
}

int networkfs_helper_remove_file_or_dir(struct inode *parent,
                                        struct dentry *child, char *method) {
  const char *name = child->d_name.name;
  if (child->d_name.len > 255) {
    printk(KERN_ERR
           "networkfs remove_file_or_dir: name length is greater than 255");
    return -1;
  }

  char ino_as_string[22];
  sprintf(ino_as_string, "%lu", parent->i_ino);
  int response_status =
      networkfs_http_call(get_token(parent), method, NULL, 0, 2, "parent",
                          ino_as_string, "name", name);
  if (response_status) {
    printk(KERN_ERR
           "networkfs remove_file_or_dir: HTTP request has failed: response "
           "status %d\n",
           response_status);
    return response_status;
  }

  return 0;
}

int networkfs_unlink(struct inode *parent, struct dentry *child) {
  return networkfs_helper_remove_file_or_dir(parent, child, "unlink");
}

int networkfs_rmdir(struct inode *parent, struct dentry *child) {
  return networkfs_helper_remove_file_or_dir(parent, child, "rmdir");
}

int networkfs_helper_create_file_or_dir(struct user_namespace *user_ns,
                                        struct inode *parent,
                                        struct dentry *child, char *type) {
  const char *name = child->d_name.name;
  if (child->d_name.len > 255) {
    printk(KERN_ERR
           "networkfs create_file_or_dir: name length is greater than 255");
    return -1;
  }
  char ino_as_string[22];
  sprintf(ino_as_string, "%lu", parent->i_ino);

  size_t response_buffer_size = sizeof(ino_t);
  char *response_buffer = kmalloc(response_buffer_size, GFP_KERNEL);
  if (!response_buffer) {
    printk(KERN_ERR
           "networkfs create_file_or_dir: could not allocate memory for "
           "response buffer");
    return 0;
  }
  int response_status = networkfs_http_call(
      get_token(parent), "create", response_buffer, response_buffer_size, 3,
      "parent", ino_as_string, "name", name, "type", type);
  if (response_status) {
    printk(KERN_ERR
           "networkfs create_file_or_dir: HTTP request has failed: response "
           "status %d\n",
           response_status);
    return response_status;
  }

  ino_t ino = *(ino_t *)response_buffer;
  struct inode *inode = networkfs_get_inode(
      parent->i_sb, parent,
      (!strcmp(type, "file") ? S_IFREG : S_IFDIR) | S_IRWXU | S_IRWXG | S_IRWXO,
      ino);
  d_add(child, inode);

  return 0;
}

int networkfs_create(struct user_namespace *user_ns, struct inode *parent,
                     struct dentry *child, umode_t mode, bool b) {
  return networkfs_helper_create_file_or_dir(user_ns, parent, child, "file");
}

int networkfs_mkdir(struct user_namespace *user_ns, struct inode *parent,
                    struct dentry *child, umode_t mode) {
  return networkfs_helper_create_file_or_dir(user_ns, parent, child,
                                             "directory");
}

module_init(networkfs_init);
module_exit(networkfs_exit);
