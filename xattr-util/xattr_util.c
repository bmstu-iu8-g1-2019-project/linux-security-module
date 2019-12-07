#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

#define SEC_LABEL "security.bmstu_exe"

void set_gid(char *path, int gid) {
  int data[1];
  int ret = EXIT_FAILURE;

  data[0] = gid;
  ret = setxattr(path, SEC_LABEL, (char *)data, sizeof(int) + 1, 0);

  if (ret < 0) {
    perror("[-] setxattr failed");
  }
}

void clear_xattr(char *path) {
  int ret = EXIT_FAILURE;

  ret = removexattr(path, SEC_LABEL);

  if (ret < 0) {
    perror("[-] removexattr failed");
  }
}

void add_gid(char *path, int gid) {
  char *attr;
  int *data;
  int ret = EXIT_FAILURE;
  ssize_t size;

  size = getxattr(path, SEC_LABEL, NULL, 0);
  if (size < 0) {
    set_gid(path, gid);
    return;
  }

  attr = malloc(size + sizeof(int));
  if (attr == NULL) {
    printf("No memory.\n");
    return;
  }

  ret = getxattr(path, SEC_LABEL, attr, size);
  if (ret < 0) {
    perror("[-] getxattr failed");
    free(attr);
    return;
  }

  data = (int *)attr;

  // checking if gid already exists
  for (int i = 0; i < (size - 1) / sizeof(int); i++) {
    if (data[i] == gid) {
      free(attr);
      return;
    }
  }

  data[(size - 1) / sizeof(int)] = gid;
  attr[size + sizeof(int)] = '\0';

  ret = setxattr(path, SEC_LABEL, attr, size + sizeof(int), 0);

  if (ret < 0) {
    perror("[-] setxattr failed");
  }

  free(attr);
}

void rm_gid(char *path, int gid) {
  char *attr;
  int *data;
  int ret = EXIT_FAILURE;
  ssize_t size;

  size = getxattr(path, SEC_LABEL, NULL, 0);
  if (size < 0) {
    set_gid(path, gid);
    return;
  }

  attr = malloc(size);
  if (attr == NULL) {
    printf("No memory.\n");
    return;
  }

  ret = getxattr(path, SEC_LABEL, attr, size);
  if (ret < 0) {
    perror("[-] getxattr failed");
    free(attr);
    return;
  }

  data = (int *)attr;

  int i = 0;
  int count = (size - 1) / sizeof(int); // Number of gids

  // searching for gid
  for (; i < count; i++) {
    if (data[i] == gid) {
      break;
    }
  }

  // gid no exists
  if (i == count) {
    printf("No such id.\n");
    free(attr);
    return;
  }

  // shift elements to the left
  for (; i < count - 1; i++) {
    data[i] = data[i + 1];
  }

  attr[size - sizeof(int)] = '\0';

  ret = setxattr(path, SEC_LABEL, attr, size - sizeof(int), 0);

  if (ret < 0) {
    perror("[-] setxattr failed");
  }

  free(attr);
}

void print_xattr(char *path) {
  char *attr;
  int *data;
  int ret = EXIT_FAILURE;
  ssize_t size;

  size = getxattr(path, SEC_LABEL, NULL, 0);
  if (size < 0) {
    perror("[-] getxattr failed");
    return;
  }

  attr = malloc(size);
  if (attr == NULL) {
    printf("No memory.\n");
    return;
  }

  ret = getxattr(path, SEC_LABEL, attr, size);
  if (ret < 0) {
    perror("[-] getxattr failed");
    free(attr);
    return;
  }

  data = (int *)attr;

  for (int i = 0; i < (size - 1) / sizeof(int); i++) {
    printf("%d ", data[i]);
  }

  printf("\n");
  free(attr);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("No command specified. Type --help for usage.\n");
    return 0;
  }

  if (strcmp(argv[1], "--help") == 0) {
    printf("Usage:\n");
    printf("xattr_util print <file>\n");
    printf("xattr_util add <gid> <file>\n");
    printf("xattr_util remove <gid> <file>\n");
    printf("xattr_util clear <file>\n");
    return 0;
  }

  if (argc < 3) {
    printf("Invalid arguments specified. Type --help for usage.\n");
    return 0;
  }

  if (strcmp(argv[1], "print") == 0) {
    print_xattr(argv[2]);
    return 0;
  }

  if (strcmp(argv[1], "clear") == 0) {
    clear_xattr(argv[2]);
    return 0;
  }

  if (argc < 4) {
    printf("Invalid arguments specified. Type --help for usage.\n");
    return 0;
  }

  if (strcmp(argv[1], "add") == 0) {
    add_gid(argv[3], atoi(argv[2]));
    return 0;
  }

  if (strcmp(argv[1], "remove") == 0) {
    rm_gid(argv[3], atoi(argv[2]));
    return 0;
  }

  return 0;
}
