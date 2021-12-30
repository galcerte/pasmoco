#define _POSIX_C_SOURCE 200809L
/* C standard library */
/* Seems like we need stdlib.h to be included before anything else. */
#include <stdlib.h>
#include "stdio.h"
#include <string.h> /* String manipulation */
#include <time.h>   /* Initializing seed for random generation */
/* C POSIX library */
#include <sys/stat.h> /* Checking stats of files; used here to get file size */
#include <termios.h>  /* Telling the terminal to not show input */
#include <unistd.h>   /* POSIX API, used for creating folders */
#include <monocypher.h>

#define PASS_LEN 200
#define PATH_LEN 300
#define RANDSTR_LEN 50
#define TITLE_LEN 100

void show_command_information(const int sit) {
  switch (sit) {
    case 0:
      fputs("pasmoco requires a command. Possible commands are:\n", stdout);
      fputs("init - Create the folder where passwords and index will be stored, located at $HOME/.local/share/pasmoco\n", stdout);
      fputs("add - Create a password entry\n", stdout);
      fputs("ls - List all password entries\n", stdout);
      fputs("rm - Remove a password entry\n", stdout);
      fputs("get - Retrieve a password\n", stdout);
      break;
    case 1:
      fputs("Invalid command, please provide a valid one.\n", stdout);
      fputs("Possible commands are:\n", stdout);
      fputs("init - Create the folder where passwords and index will be stored, located at $HOME/.local/share/pasmoco\n", stdout);
      fputs("add - Create a password entry\n", stdout);
      fputs("ls - List all password entries\n", stdout);
      fputs("rm - Remove a password entry\n", stdout);
      fputs("get - Retrieve a password\n", stdout);
      break;
    case 2:
      fputs("This command does not need arguments.\n", stdout);
      break;
    case 3:
      fputs("Too many arguments have been passed.\n", stdout);
  }
}

void check_folder_index(const char* dir_path, const char* index_path) {
  if (access(dir_path, F_OK) != -1) {
    if (! (access(index_path, F_OK) != -1)) {
      fputs("The index file doesn't exist. Please run \"pasmoco init\" to create it.\n", stdout);
      exit(EXIT_FAILURE);
    }
  }
  else {
    fputs("The folder at ", stdout);
    fputs(dir_path, stdout);
    fputs(" doesn't exist. Please run \"pasmoco init\" to create both it and the index file within.\n", stdout);
    exit(EXIT_FAILURE);
  }
}

/* Fetching password from stdin, not letting it show up on the terminal */
void password_input(char* pass, size_t pass_len) {
  /* These 5 lines down here are required for preventing password input from being shown */
  struct termios oldt;
  tcgetattr(STDIN_FILENO, &oldt);
  struct termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  /* Here's the actual input */
  fgets(pass, pass_len, stdin);
  /* And the terminal is brought back to how it was */
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

/* Generating a random string */
char* rand_junk_str(char* str, size_t size) {
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  if (size) {
    --size;
    for (size_t n = 0; n < size; n++) {
      /* I won't use rand() for crypto, so don't panic. */
      int key = rand() % (int) (sizeof charset - 1);
      str[n] = charset[key];
    }
    str[size] = '\0';
  }
  return str;
}

off_t get_file_size(const char* path) {
  /* fp == file pointer */
  FILE* fp = fopen(path, "r");
  int fd = fileno(fp);

  if (fd == -1) {
    fputs("Could not read index file. Aborting.", stdout);
    fclose(fp);
    exit(EXIT_FAILURE);
  }

  struct stat buf;
  /* With fstat() we get file attributes and put them in buf. buf.st_size is the size of the file in bytes. */
  int stat = fstat(fd, &buf);
  if ((stat != 0) || (!S_ISREG(buf.st_mode))) {
    fputs("Could not read index file. Aborting.", stdout);
    fclose(fp);
    exit(EXIT_FAILURE);
  }

  off_t file_size = buf.st_size;
  /* I'll set a large upper limit for the file, 1 MB. */
  if (file_size > 1000000) {
    fputs("Index file is larger than 1 MB. Aborting.", stdout);
    fclose(fp);
    exit(EXIT_FAILURE);
  }
  fclose(fp);
  return file_size;
}

/* The way this function parses the index file puts the entire second column of the CSV index file
 * into titles[], which means that "Titles" will invariably be the first string in that array.
 * We won't ignore that when parsing, but we will ignore it when printing titles[], simply by starting
 * from titles[1] and not titles[0] */
void get_titles_from_index(char** titles, const size_t lines, const char* buffer, const size_t buf_len) {
  /* which char in the buffer are we at... */
  unsigned int n = 0;
  /* which string are we at... */
  unsigned int str = 0;
  /* which char in the string are we at... */
  unsigned int c = 0;

  /* In this loop, we're just walking through each character of the 1D array that is the file
     buffer, until we reach the last element of the array */
  while (n < buf_len) {
    /* If we find a comma, that means we've reached a title. */
    if (buffer[n] == ',') {
      /* We advance by one char, and find the first char of the title, */
      n++;
      /* And set a variable which will be the index of the string where the title'll be stored */
      c = 0;
      /* Now, we walk char by char through the buffer again, storing characters in the string at
         titles[p] until we find a newline char, and until the end of the file, */
      while (buffer[n] != '\n' && n < buf_len) {
        if (c < TITLE_LEN && str < lines){
          titles[str][c] = buffer[n];
        }
        c++;
        n++;
      }
      /* Since this is done char by char, instead of treating everything with string manipulation
       * functions, we need to add the termination character at the end of the string, */
      if (c < TITLE_LEN && str < lines){
        titles[str][c] = '\0';
        c++;
      }
      /* And if we're not at the end of the buffer, we jump to the next title string */
      if (n < buf_len) {
        str++;
      }
    }
    n++;
  }
}

/* "Filenames" will also be the first string in filenames[], as above, so that'll have to be compensated for, later */
void get_filenames_from_index(char** filenames, const size_t lines, const char* buffer, const size_t buf_len) {
  /* Same as indicated in the above function */
  unsigned int n = 0;
  unsigned int str = 0;
  unsigned int c = 0;

  while (n < buf_len) {
    /* So we start out parsing what is already a filename, given that the first
     * column is that. */
    if (buffer[n] == ',') {
      /* If we find a comma, we null terminate the filename. Just as a sanity check, I
       * make sure I'm not writing that character whereever... */
      if (c - 1 < RANDSTR_LEN && str < lines){
        filenames[str][c - 1] = '\0';
      }
      /* Now we just ignore every character until we find a newline character, */
      while (buffer[n] != '\n' && n < buf_len) {
        n++;
      }
      /* Now n should be at the element of buffer[] where there's a newline, so
       * it's time to write to the next string in filenames[][] */
      if (n < buf_len) {
        str++;
      }
      /* And advance n by one, so that it's at the first char of a filename */
      n++;
    }
    filenames[str][c] = buffer[n];
    c++;
    n++;
  }
}

unsigned int get_entry_from_user(char** titles, const unsigned int lines) {
  char option[TITLE_LEN] = {0};
  int match = 1;
  unsigned int sel = 0;

  do {
    fputs("Entry: ", stdout);
    fgets(option, TITLE_LEN, stdin);
    for (unsigned int n = 1; n < lines; n++) {
      match = strncmp(titles[n], option, TITLE_LEN);
      if (! match) {
        sel = n;
        break;
      }
    }
    if (match) {
      fputs("Incorrect entry.\n", stdout);
    }
  } while (match != 0);
  return sel;
}

int encrypt(const char* dest_file_path, const char* message, const size_t message_len) {
  unsigned char salt[crypto_pwhash_SALTBYTES] = {0};
  unsigned char key[crypto_secretbox_KEYBYTES] = {0};
  char mast_pass[PASS_LEN] = {0};

  fputs("Master password: ", stdout);
  password_input(mast_pass, PASS_LEN);
  fputs("\n", stdout);
  /* Salt generation */
  randombytes_buf(salt, sizeof(salt));
  /* Key generation from password */
  if (crypto_pwhash(key, sizeof(key), mast_pass, strlen(mast_pass), salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
    fputs("Ran out of memory while deriving key from master password. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  /* Actual encryption */
  unsigned char ciphertext[message_len + crypto_secretbox_MACBYTES];
  crypto_secretbox_easy(ciphertext, (unsigned char*)message, message_len, salt, key);
  /* Writing encrypted contents into file */
  FILE* dest_fp = fopen(dest_file_path, "wb");
  if (! dest_fp) {
    fputs("Failed to open file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  fwrite(ciphertext, 1, message_len + crypto_secretbox_MACBYTES, dest_fp);
  fclose(dest_fp);
  return 0;
}

/* File decryption is always failing because a different salt is used every time */
int decrypt(const char* src_file_path, const char* message, const size_t message_len) {
  unsigned char salt[crypto_pwhash_SALTBYTES] = {0};
  unsigned char key[crypto_secretbox_KEYBYTES] = {0};
  char mast_pass[PASS_LEN] = {0};

  fputs("Master password: ", stdout);
  password_input(mast_pass, PASS_LEN);
  fputs("\n", stdout);
  /* Salt generation */
  randombytes_buf(salt, sizeof(salt));
  /* Key generation */
  if (crypto_pwhash(key, sizeof(key), mast_pass, strlen(mast_pass), salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
    fputs("Ran out of memory while deriving key from master password. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  /* Reading encrypted file */
  FILE* dest_fp = fopen(src_file_path, "rb");
  if (! dest_fp) {
    fputs("Failed to open file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  unsigned char ciphertext[message_len + crypto_secretbox_MACBYTES];
  fread(ciphertext, sizeof(char), message_len + crypto_secretbox_MACBYTES, dest_fp);
  /* Decryption */
  if (crypto_secretbox_open_easy((unsigned char*)message, ciphertext, message_len + crypto_secretbox_MACBYTES, salt, key) != 0) {
    fputs("File contents have been forged or corrupted. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  fclose(dest_fp);
  return 0;
}

void initialize(const char* dir_path, const char* index_path) {
  if (access(dir_path, F_OK) != -1) {
    fputs("The folder at ", stdout);
    fputs(dir_path, stdout);
    fputs(" exists.\n", stdout);
    if (access(index_path, F_OK) != -1) {
      fputs("The index file at ", stdout);
      fputs(index_path, stdout);
      fputs(" exists as well. No action necessary.\n", stdout);
    }
    else {
      fputs("Creating index file within folder.\n", stdout);
      if (encrypt(index_path, "Filename,Title", strlen("Filename,Title")) != 0) {
        fputs("Failed to encrypt index file. Aborting.\n", stdout);
        exit(EXIT_FAILURE);
      }
    }
  }
  else {
    fputs("The folder at ", stdout);
    fputs(dir_path, stdout);
    fputs(" doesn't exist. Creating it.\n", stdout);
    if (mkdir(dir_path, 0700) == -1) {
      fputs("Creating folder failed. Aborting.\n", stdout);
      exit(EXIT_FAILURE);
    }
    else {
      fputs("Creating index file within folder.\n", stdout);
      if (encrypt(index_path, "Filename,Title", strlen("Filename,Title")) != 0) {
        fputs("Failed to encrypt index file. Aborting.\n", stdout);
        exit(EXIT_FAILURE);
      }
    }
  }
}

/* Adding a password to the folder, and adding the random filename to the index */
void add_password(const char* index_path, char* file_path) {
  char rand_str[RANDSTR_LEN] = {0};
  /* We initialize the seed for generating random strings. Now, this might be a shitty way to get a seed, but all
   * I want is some junk to put as a filename, it's not a mission critical task */
  srand(time(0));
  rand_junk_str(rand_str, RANDSTR_LEN);
  snprintf(file_path + strlen(file_path), PATH_LEN - strlen(file_path), "%s", rand_str);

  char title[TITLE_LEN] = {0};
  char password[PASS_LEN] = {0};
  char username[100] = {0};
  char url[200] = {0};
  char notes[1000] = {0};

  fputs("Title: ", stdout);
  fgets(title, TITLE_LEN, stdin);

  fputs("Password: ", stdout);
  password_input(password, PASS_LEN);
  fputs("\n", stdout);

  fputs("Username: ", stdout);
  fgets(username, 100, stdin);

  fputs("URL: ", stdout);
  fgets(url, 200, stdin);

  fputs("Notes: ", stdout);
  fgets(notes, 1000, stdin);

  /* strlen() excludes the null byte, but strcat() includes it, so when allocating the entire
   * entry on the stack, we need to take that into account. We need 5 extra elements for the
   * null bytes at the end, and 4 new line characters. */
  unsigned int entry_len = strlen(title) + strlen(password) + strlen(username) + strlen(url) + strlen(notes) + 9;
  char entry[entry_len];
  /* snprintf() however does include the null byte, even when writing entry_len characters to entry */
  snprintf(entry, entry_len, "%s%s%s%s%s%s%s%s%s", title, "\n", password, "\n", username, "\n", url, "\n", notes);
  if (encrypt(file_path, entry, entry_len) != 0) {
    fputs("Unable to encrypt password file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  /* Now, we append the title of the entry and corresponding randomized filename to the end of the index file */
  size_t index_len = ((size_t)get_file_size(index_path) - crypto_secretbox_MACBYTES)/sizeof(char);
  char* index_buf = calloc(index_len + RANDSTR_LEN + strlen(title) + 1, sizeof(char));
  if (decrypt(index_path, index_buf, index_len) != 0) {
    fputs("Unable to decrypt index file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  snprintf(index_buf + index_len, RANDSTR_LEN + 1 + strlen(title), "%s%s%s", rand_str, ",", title);
  /* Append index_entry to index_buf, overwrite index_path with encrypt() */
  if (encrypt(index_path, index_buf, index_len + RANDSTR_LEN + strlen(title) + 1) != 0) {
    fputs("Unable to encrypt index file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
}

void list_passwords(const char* index_path) {
  size_t index_len = ((size_t)get_file_size(index_path) - crypto_secretbox_MACBYTES)/sizeof(char);
  char* index_buf = calloc(index_len, sizeof(char));

  if (! index_buf) {
    fputs("Failed to allocate needed memory for reading index file. Aborting.", stdout);
    exit(EXIT_FAILURE);
  }
  if (decrypt(index_path, index_buf, index_len) != 0) {
    fputs("Unable to decrypt index file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  unsigned int lines = 0;
  for (unsigned int n = 0; n < index_len; n++) {
    if (index_buf[n] == '\n') {
      lines++;
    }
  }
  /* We allocate the first "column", of the 2D char array, */
  char** titles = calloc(lines, sizeof(char));
  if (! titles) {
    fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
    free(titles);
    free(index_buf);
    exit(EXIT_FAILURE);
  }
  for (unsigned int n = 0; n < lines; n++) {
    /* Then the memory for each "row" */
    titles[n] = calloc(TITLE_LEN, sizeof(char));
    if (! titles[n]) {
      fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
      for (int m = n; m >= 0; m--) free(titles[m]);
      free(titles);
      free(index_buf);
      exit(EXIT_FAILURE);
    }
  }
  get_titles_from_index(titles, lines, index_buf, index_len);
  free(index_buf);
  /* Printing list of titles */
  for (unsigned int n = 0; n < lines; n++) {
    fputs(titles[n], stdout);
    fputs("\n", stdout);
  }
  for (int m = lines - 1; m >= 0; m--) free(titles[m]);
  free(titles);
}

void rm_password(const char* index_path, char* file_path) {
  size_t index_len = ((size_t)get_file_size(index_path) - crypto_secretbox_MACBYTES)/sizeof(char);
  char* index_buf = calloc(index_len, sizeof(char));

  if (! index_buf) {
    fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  if (decrypt(index_path, index_buf, index_len) != 0) {
    fputs("Unable to decrypt index file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  unsigned int lines = 0;
  for (unsigned int n = 0; n < index_len; n++) {
    if (index_buf[n] == '\n') {
      lines++;
    }
  }
  /* Now we allocate memory for the entry titles */
  char** titles = calloc(lines, sizeof(char));
  if (! titles) {
    fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
    free(titles);
    free(index_buf);
    exit(EXIT_FAILURE);
  }
  for (unsigned int n = 0; n < lines; n++) {
    titles[n] = calloc(TITLE_LEN, sizeof(char));
    if (! titles[n]) {
      fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
      for (int m = n; m >= 0; m--) free(titles[m]);
      free(titles);
      free(index_buf);
      exit(EXIT_FAILURE);
    }
  }
  /* And now we parse the index file, filling titles[] up */
  get_titles_from_index(titles, lines, index_buf, index_len);
  /* Title printing to stdout */
  for (unsigned int n = 1; n < lines; n++) {
    fputs(titles[n], stdout);
    fputs("\n", stdout);
  }
  /* User selects entry */
  unsigned int sel = get_entry_from_user(titles, lines);
  free(titles);
  /* Same thing as we did with titles, we do with the randomized filenames */
  char** filenames = calloc(lines, sizeof(char));
  if (! filenames) {
    fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
    free(filenames);
    free(index_buf);
    exit(EXIT_FAILURE);
  }
  for (unsigned int n = 0; n < lines; n++) {
    filenames[n] = calloc(RANDSTR_LEN, sizeof(char));
    if (! filenames[n]) {
      fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
      for (int m = n; m >= 0; m--) free(filenames[m]);
      free(filenames);
      free(index_buf);
      exit(EXIT_FAILURE);
    }
  }
  /* And now we parse the index file again, filling filenames[] up */
  get_filenames_from_index(filenames, lines, index_buf, index_len);
  /* Now that we know which password file the user wants to delete,
   * we complete file_path */
  snprintf(file_path + strlen(file_path), sizeof(file_path) - strlen(file_path), "%s", filenames[sel]);
  /* So now we can delete the indicated password file. Now, using
   * remove() might not be the most adequate way to remove a file
   * which has sensitive information, I might look into using
   * something better later */
  if (! remove(file_path)) {
    fputs("Successfully deleted selected password file.\n", stdout);
  }
  else {
    fputs("Failed to delete selected password file. Aborting.\n", stdout);
    free(index_buf);
    for (int m = lines - 1; m >= 0; m--) free(filenames[m]);
    free(filenames);
    exit(EXIT_FAILURE);
  }
  /* Entry is deleted from index file */
  for (int m = lines - 1; m >= 0; m--) free(filenames[m]);
  free(filenames);
  /* Index file encryption */
  if (encrypt(index_path, index_buf, index_len) != 0) {
    fputs("Failed to encrypt index file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  free(index_buf);
}

void get_password(const char* index_path, char* file_path) {
  size_t index_len = ((size_t)get_file_size(index_path) - crypto_secretbox_MACBYTES)/sizeof(char);
  char* index_buf = calloc(index_len, sizeof(char));
  if (! index_buf) {
    fputs("Failed to allocate needed memory for reading index file. Aborting.", stdout);
    exit(EXIT_FAILURE);
  }
  if (decrypt(index_path, index_buf, index_len) != 0) {
    fputs("Unable to decrypt index file. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  unsigned int lines = 0;
  for (unsigned int n = 0; n < index_len; n++) {
    if (index_buf[n] == '\n') {
      lines++;
    }
  }
  /* Allocating memory on the heap for password entry titles */
  char** titles = calloc(lines, sizeof(char));
  if (! titles) {
    fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
    free(titles);
    free(index_buf);
    exit(EXIT_FAILURE);
  }
  for (unsigned int n = 0; n < lines; n++) {
    titles[n] = calloc(TITLE_LEN, sizeof(char));
    if (! titles[n]) {
      fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
      for (int m = n; m >= 0; m--) free(titles[m]);
      free(titles);
      free(index_buf);
      exit(EXIT_FAILURE);
    }
  }
  /* Getting titles from the buffer of the index file in memory, */
  get_titles_from_index(titles, lines, index_buf, index_len);
  /* Now they're printed, */
  for (unsigned int n = 0; n < lines; n++) {
    fputs(titles[n], stdout);
    fputs("\n", stdout);
  }
  /* User selects entry */
  unsigned int sel = get_entry_from_user(titles, lines);
  for (int m = lines - 1; m >= 0; m--) free(titles[m]);
  free(titles);
  /* We do all the same stuff we did for titles, */
  char** filenames = calloc(lines, sizeof(char));
  if (! filenames) {
    fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
    free(filenames);
    free(index_buf);
    exit(EXIT_FAILURE);
  }
  for (unsigned int n = 0; n < lines; n++) {
    filenames[n] = calloc(TITLE_LEN, sizeof(char));
    if (! filenames[n]) {
      fputs("Failed to allocate needed memory for reading index file. Aborting.\n", stdout);
      for (int m = n; m >= 0; m--) free(filenames[m]);
      free(filenames);
      free(index_buf);
      exit(EXIT_FAILURE);
    }
  }
  /* Same here, */
  get_filenames_from_index(filenames, lines, index_buf, index_len);
  /* And concatenate the right filename to file_path, so now we can actually decrypt the right file */
  snprintf(file_path + strlen(file_path), PATH_LEN - strlen(file_path), "%s", filenames[sel]);
  /* Password file decryption */
  size_t file_len = ((size_t)get_file_size(file_path) - crypto_secretbox_MACBYTES)/sizeof(char);
  char* file_buf = calloc(file_len, sizeof(char));
  if (decrypt(file_path, file_buf, file_len) != 0) {
    fputs("Unable to decrypt password file. Aborting.\n", stdout);
    free(file_buf);
    exit(EXIT_FAILURE);
  }
  /* Password is printed to stdout. I need to check if this buffer is null terminated or not */
  free(index_buf);
  fputs(file_buf, stdout);
  free(file_buf);
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    /* This first case below executes when just the binary's name has been invoked.
     * Can't declare and define variables within the switch statement, so gotta check
     * early if there's just the executable name, that way we don't check argv[1]
     * if it doesn't exist, we can't do that since it's undefined behaviour */
    show_command_information(0);
    exit(EXIT_SUCCESS);
  }

  if (sodium_init() < 0) {
    fputs("File encryption is not available. Aborting.\n", stdout);
    exit(EXIT_FAILURE);
  }
  
  int init = strncmp(argv[1], "init", 20);
  int add = strncmp(argv[1], "add", 20);
  int ls = ((strncmp(argv[1], "ls", 20) == 0) || (strncmp(argv[1], "list", 20) == 0) || (strncmp(argv[1], "show", 20) == 0)) ? 0 : 1;
  int rm = strncmp(argv[1], "rm", 20);
  int get = strncmp(argv[1], "get", 20);
  char home_path[100] = {0};
  char dir_path[200] = {0};
  char index_path[PATH_LEN] = {0};
  char file_path[PATH_LEN] = {0};

  snprintf(home_path, 100, "%s", getenv("HOME"));
  snprintf(dir_path, 200, "%s", getenv("PASMOCO_DIR"));
  if (! (strncmp(dir_path, "(null)", 200))) snprintf(dir_path, 200, "%s%s", home_path, "/.local/share/pasmoco");
  snprintf(file_path, PATH_LEN, "%s%s", dir_path, "/");
  snprintf(index_path, PATH_LEN, "%s%s", dir_path, "/index");

  switch (argc) {
  case 2:
    if (init == 0) {
      initialize(dir_path, index_path);
    }
    else if (add == 0) {
      check_folder_index(dir_path, index_path);
      add_password(index_path, file_path);
    }
    else if (ls == 0) {
      check_folder_index(dir_path, index_path);
      list_passwords(index_path);
    }
    else if (rm == 0) {
      check_folder_index(dir_path, index_path);
      rm_password(index_path, file_path);
    }
    else if (get == 0) {
      check_folder_index(dir_path, index_path);
      get_password(index_path, file_path);
    }
    else {
      show_command_information(1);
    }
    break;
  case 3:
    if (init == 0) {
      show_command_information(2);
    }
    else if (add == 0) {
      show_command_information(2);
    }
    else if (ls == 0){
      show_command_information(2);
    }
    else if (rm == 0) {
      show_command_information(2);
    }
    else if (get == 0) {
      show_command_information(2);
    }
    else {
      show_command_information(1);
    }
    break;
  default:
    show_command_information(3);
  }
  return EXIT_SUCCESS;
}
