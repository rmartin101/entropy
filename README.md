# Entropy 

This short program computes the entropy of network traffic files assuming all values are independent. Recall in a network traffic file, the first value is the time (jitter), the second is the size of the packet. Each record is a binary pair of little endian 32 bit floating point values (for x86). Measuring the dependence of values is beyond the scope of this work. 

The program also has a second mode to generate test cases to check that the entropy is computed correctly.  The test case covers a range of values from 0-max_range,  with either a deterministic, uniform or normal distribution.












