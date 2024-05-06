/* C program to compute the entropy values of data files 
 * (C) 2024 R. P. Martin. Licensed under GNu Public License (GPL), Version 3
 *
 * This short program computes the entropy of network traffic files.
 * recall in a network traffic file, the first value is the time (jitter), 
 * the second is the size of the packet. Each record is a binary pair of 
 * little endian 32 bit floating point values (for x86).
 *
 * The program also has a second mode to generate test cases
 * to check that the entropy is computed correctly.
 * The test case covers a range of values from 0-max_range, 
 * with either a deterministic, uniform or normal distribution.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <float.h>
#include <math.h>
#include <string.h> 
#include <sys/mman.h>
#include <sys/stat.h>

/* distributions for generating test cases */
#define DETERMINISTIC 0 
#define UNIFORM 1
#define NORMAL 2

/* function to return values according to a normal disribution using 
 * the 
 * note that the generator must use a cos, sin pair in the output stream.
 * so there is a static variable to remember if it should return the cosine 
 * or sin. 
*/ 
float nextnormal(float mean, float stddev) {
  static float z1; // To hold the additional generated number
  static int generate = 0; // Toggle flag to use stored number
  float u1, u2, z0;

  if (!generate) {
    /* Generate u1 and u2, two independent random numbers uniformly distributed between 0 and 1 */
    u1 = rand() / (RAND_MAX + 1.0);
    u2 = rand() / (RAND_MAX + 1.0);

    /*  Apply the Box-Muller transform to generate two independent normally distributed random numbers */
    z0 = sqrt(-2.0 * log(u1)) * cos(2 * M_PI * u2);
    z1 = sqrt(-2.0 * log(u1)) * sin(2 * M_PI * u2);

    /* Scale and shift by mean and standard deviation */
    z0 = z0 * stddev + mean;
    z1 = z1 * stddev + mean;

    generate = 1; /* Next call uses z1 */
    return z0;
  } else {
    generate = 0; /*  Reset for next full generation */
    return z1;
  }
}

/* small program to generate test data and save it to a file */
int genTestData(char *filename,int num_samples, int distribution, double range,double stdev) {
  int i; 
  float size,time;
  float record[2]; 
  double mean; 
  FILE *file;

  mean = range/2.0;
  
  /* open the file for writing, erasing prior content */
  file = fopen(filename, "wb");
  if (file == NULL) {
    perror("Failed to open file");
    return EXIT_FAILURE;
  }

  /* loop writing the record values */ 
  size = time =  0.0; 
  for (i =0 ; i< num_samples ; i++ ){

    switch (distribution) {
    case DETERMINISTIC:
      if (size >= range) {
	time = size = 0.0; 
      } else { 
	time = time +1.0;
	size = size +1.0; 
      }
      break;
    case UNIFORM:
      time = (rand() / (RAND_MAX + 1.0))*range;
      size = (rand() / (RAND_MAX + 1.0))*range;
      break;
    case NORMAL:
      time = nextnormal(mean,stdev);
      size = nextnormal(mean,stdev);
      break;
    default:
      fprintf(stderr,"invalid distribution %d, exiting \n", distribution);
      exit(-1);
      break;
    }

    // Write the float to the file
    record[0]=time;
    record[1]=size; 
    if (fwrite(record, sizeof(float), 2, file) != 2) {
      perror("Failed to write float record to file");
      fclose(file);
      return EXIT_FAILURE;
    }
  }
  
  /* close the file */
  fclose(file);
  return 1; 
}


/* this functions take a dataset and empty histogram as input, and computes the entropy 
 * it just uses the Shannon defintion of entropy by summing up the probabilities of each
 * bucket in the histogram 
 */  
double compute_entropy(float *base_data_p,   /* pointer to the base data of record pairs */
		       unsigned int max_elements,   /* number of elements in the base data to process */
		       unsigned int values_per_record,  /* which field in the record from the base array to access. Assumes every value is a 32 bit little endian float */ 
		       unsigned int *bucket_array,  /* base pointer to the number of buckets */ 
		       unsigned int num_buckets,    /* number of buckers in the bucket array */ 
		       double min, double max,      /* min and max of the floats in the records */ 
		       double min_prob) {         /* minum probablity to add, avoid adding NANs to the result */
  unsigned int i; 
  double bucket_size;
  float *current_record_p;
  double max_elements_d; 
  float value;
  unsigned int bucket_num;
  double prob, sum,prob_sum,entropy;

  max_elements_d = (double) max_elements; /* max elements as a double, not int */ 
  bucket_size = (double) (max-min)/ (double) num_buckets;
  current_record_p = (float *) base_data_p ;
  prob_sum = 0.0;
  
  /* run through all the values and compute the number of elements in each bucket in the histogram */
  for (i = 0; i < max_elements; i++) {
    value = *current_record_p;

    /* get the actual bucket number 
     * since we can have negative times, we must make sure the shift resets the base range to zero 
     * for the histogram to based at a zero index  
     * we have to shift ny the min to make sure the histrogram is based at zero */
    bucket_num = (unsigned int) ( (value - min) / bucket_size );

    /* make sure all the values are in the correct ranges and complain if not */     
    if ((bucket_num) < 0 ) {
      printf("warning, got time bucket <0, value %0.3f resetting to zero at record %d \n",value,i);
      bucket_num =0; 
    }
    if ((bucket_num) > num_buckets) {
      printf("warning, got bucket > %d, value %0.3f resetting to max at record %d \n",num_buckets,value,i);
      bucket_num = (num_buckets-1) ;
    }

    /* update the count in the actual buckets */
    bucket_array[bucket_num] += 1;
    
    current_record_p += values_per_record;
  } /* loop to run through all the values */

  /* We build the histogram, now compute the actual entropy */
  for (i = 0, sum =0.0; i < num_buckets; i++) {
    /* the probability is just the number in the bucket divided by the total number of samples */
    prob = (double) bucket_array[i]/ max_elements_d;
    prob_sum = prob_sum + prob; 
    /* if the probability is too small, we get weird effects adding NANs and very small values 
     * this is the cut-off for being too small */ 
    if (prob > min_prob) { 
      sum = sum + (prob * log2(prob));
    }
  }
  entropy = -1.0 * sum;

  printf("Check, probabilities should sum to 1 %lf \n", prob_sum);
  
  return entropy;
  
} /* end compute_entropy */ 



int main(int argc, char *argv[]) {
  int i;                     /* generic loop counter */ 
  int opt;                   /* for option parsing */ 
  char *filename;            /* input filename */
  int fd;                    /* the file descriptor */
  struct stat sb;            /* check if mmap worked with a stat struct */
  
  int max_records;           /* maximum number of records of size/time */
  int max_records_in_file;      /* find the maximum records in the file */
  int highest_record ;       /* the record we actually goto */
  int print_records;         /* print the records out */ 
  int print_histogram;       /* print the histograms */
  
  unsigned long num_times;    /* total number of time records */
  unsigned long num_sizes;    /* total number of time records */
  
  void *base_file_p;          /* base pointer to the input file */ 
  float *current_time_p;     /* pointer to the current time */ 
  float *current_size_p;     /* pointer to the current size */ 
  float time, size;          /* actual values to read in */
  float min_time, max_time;  /* ranges for the times */ 
  float min_size, max_size;  /* ranges for the sizes */
  int num_time_buckets;      /* the discrete histogram of time values */ 
  int num_size_buckets;      /* the discrete histogram of size values */
  
  unsigned int *time_buckets;  /* holds the histogram of times */
  unsigned int *size_buckets;  /* holds the histogram of sizes */
  unsigned int t_bucket;       /* the actual time bucket ID for the time we read in */
  unsigned int s_bucket;       /* the actual size bucket ID for the size we read in */
  float time_bucket_size;      /* the range of a single time bucket */
  float size_bucket_size;      /* the range of a single size bucket */

  double min_prob;               /* min prob to add to avoid nan underflow */ 
  double t_entropy, s_entropy;  /* the actual entropy */

  double gen_range, gen_stdev;   /* range and std deviation for test case file */
  int distribution ;             /* distribution to use for test-case file */
  
  filename = (char *) NULL; 
  max_records = 0;
  base_file_p = (void *) NULL ;
  print_records = print_histogram = 0;
  
  num_time_buckets = 1000;
  num_size_buckets = 1000;
  /* default values to find the ranges of times and sizes */ 
  min_time = FLT_MAX ;
  min_size = FLT_MAX ;
  max_time = FLT_MIN ;
  max_size = FLT_MIN ;

  t_entropy = s_entropy = 0.0;
  min_prob = 0.0000001;

  gen_range = gen_stdev = 0.0;
  distribution = UNIFORM;

  
  /* set the seed for the normal distribution generator */ 
  srand(0xDEADBEEF); // Seed the random number generator
  /* Parse input arguments  */
  while ((opt = getopt(argc, argv, "f:m:t:s:p:g:v:d:hr")) != -1) {
    switch (opt) {
    case 'f':
      filename = optarg; 
      break;
    case 'm':
      if ( sscanf(optarg,"%d",&max_records) != 1) {
	  fprintf(stderr, "error reading max records\n");
	  exit(EXIT_FAILURE);	
      }
      break;
    case 't':
      if ( sscanf(optarg,"%d",&num_time_buckets) != 1) {
	fprintf(stderr, "error reading number of time bucket\n");
	exit(EXIT_FAILURE);	
      }
      break;
    case 's':
      if ( sscanf(optarg,"%d",&num_size_buckets) != 1) {
	fprintf(stderr, "error reading number of size bucket\n");
	exit(EXIT_FAILURE);	
      }
      break;
    case 'p':
      if ( sscanf(optarg,"%lf",&min_prob) != 1) {
	fprintf(stderr, "error reading the min probability \n");
	exit(EXIT_FAILURE);	
      }
      break;
    case 'r':
      print_records = 1; 
      break;
    case 'h':
      print_histogram = 1; 
      break;
    case 'g':
      if ( sscanf(optarg,"%lf",&gen_range) != 1) {
	fprintf(stderr, "error reading the generator range \n");
	exit(EXIT_FAILURE);	
      }
      break;
    case 'v':
      if ( sscanf(optarg,"%lf",&gen_stdev) != 1) {
	fprintf(stderr, "error reading the generator stdev \n");
	exit(EXIT_FAILURE);	
      }
      break;
    case 'd':
      if ( sscanf(optarg,"%u",&distribution) != 1) {
	fprintf(stderr, "error reading the distribution \n");
	exit(EXIT_FAILURE);	
      }
      break; 
    default:
      fprintf(stderr, "Usage: %s [-f <filename> -m <max records> -t <time buckets> -s <size_buckets> -p <min_prob> -r (print records) -h (print histogram) -g <generaror-range> -v <generator stddev> -d distribution  \n", argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  /* test for the filename. Either one for reading the data, or one for writing the synthetically generated samples. */
  if ( filename == (char *) NULL) {
    fprintf(stderr, "no filename specified, exiting\n");
    exit(EXIT_FAILURE);	    
  };


  /* if the generator range is not zero, we run the generator an then exit */ 
  if (gen_range != 0.0) {

    if (max_records <=0 ){
      fprintf(stderr, " must set a number of records for the generator \n");      
      exit(EXIT_FAILURE);
    }

    /* check if the distribution is sane */ 
    if ( (distribution == NORMAL) && (gen_stdev == 0.0) ) {
      fprintf(stderr, " must set a standard deviation for normal distributions \n");      
      exit(EXIT_FAILURE);      
    }
    
    i =  genTestData(filename,max_records,distribution, gen_range,gen_stdev); 
    exit(EXIT_SUCCESS); 
  } /* end generate test sequence code */ 


    /* open the file with mmap */
  fd = open(filename, O_RDWR);
  if (fd == -1) {
    fprintf(stderr,"Error opening file %s", filename);
    return EXIT_FAILURE;
  }

  /* get the file size of the via stat */ 
  if (fstat(fd, &sb) == -1) {
    perror("Could not get the file size");
    close(fd);
    return EXIT_FAILURE;
  }

  /* mmap the input file of records as read-only */ 
  base_file_p = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (base_file_p == MAP_FAILED) {
    perror("Error mmapping the file");
    close(fd);
    return EXIT_FAILURE;
  }

  /* warn if not an integral number of records */ 
  if ( (sb.st_size % (2*sizeof(float))) != 0 )  {
    printf("warning, file in not an integral number of records \n");
  }
  max_records_in_file = (sb.st_size/(2*sizeof(float)));
  
  /* Now base_p (base pointer) can be used to access the file contents */
  printf("File '%s' has been memory-mapped at address %p size %lu \n", filename, base_file_p,sb.st_size);

  /* find the maximum size and maximum time */
  if ( max_records == 0) {
    highest_record = max_records_in_file;
  } else {
    highest_record = max_records;
  }

  /* this loop runs through all the times and sizes to find the range (min and max) */
  current_time_p = (float *) base_file_p ;
  current_size_p=  current_time_p +1 ;
  for (i = 0; i < highest_record; i++) {
    time = *current_time_p;
    size = *current_size_p;

    if (print_records == 1){
      printf("record: %d %0.5lf : %0.2lf \n",i,time,size);
    }
    /* find the minimum and maximum times */ 
    if (time < min_time) {
      min_time = time; 
    }
    if (time > max_time) {
      max_time = time; 
    }

    /* find the minimum and maximum sizes */
    if (size < min_size) {
      min_size = size; 
    }
    if (size > max_size) {
      max_size = size; 
    }

    /* advance the pointers in the file */
    current_time_p +=2;  /* should be RECORD_SIZE to make more general */ 
    current_size_p +=2;    
  }

  printf("time range: [%.3f:%.f]   size range: [%f:%f] \n",min_time,max_time, min_size,max_size);
  
  /* these are the actual arrays that hold the histogram buckets */ 
  time_buckets = malloc(num_time_buckets * sizeof(int));
  memset((void *) time_buckets,0,num_time_buckets * sizeof(int));
  
  size_buckets = malloc(num_size_buckets * sizeof(int));
  memset((void *) size_buckets,0,num_size_buckets * sizeof(int));  

  /* compute the actual entropy. Once for time and once for size */ 
  current_time_p = (float *) base_file_p ;
  current_size_p =  &(current_time_p[1]);  /* set to the address of the first element in a floating point array */
  t_entropy = compute_entropy(current_time_p, highest_record, 2, time_buckets, num_time_buckets, min_time, max_time, min_prob);
  s_entropy = compute_entropy(current_size_p, highest_record, 2, size_buckets, num_size_buckets, min_size, max_size, min_prob);
  printf("Time entropy: %lf  Size entropy: %lf \n", t_entropy, s_entropy);

  /* check if the histogram sums up to the max number of elements */
  if (print_histogram == 1) {
    printf("time histogram" );
    for (i = 0 ; i < num_time_buckets; i++) {
      printf(",%u",time_buckets[i]);
    }
    printf("\n");

    printf("size histogram" );
    for (i = 0 ; i < num_size_buckets; i++) {
      printf(",%u",size_buckets[i]);
    }
    printf("\n");
  }

  /* Example code showing how to properly clean up to prevent memory leaks. 
   * Its not really needed in this case though, */ 
  free(time_buckets);
  free(size_buckets);  
  
  /* Unmap and close the file. Also not needed, but nice. */ 
  if (munmap(base_file_p, sb.st_size) == -1) {
    perror("Error unmapping the file");
    close(fd);
    return EXIT_FAILURE;
  }
  close(fd);

  return 0; 
}


