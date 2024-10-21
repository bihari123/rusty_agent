 #!\/bin\/bash\r\n    # Function to check if a number is prime\r\n    is_prime() {\r\n        local num=$1\r\n        if [ $num -lt 2 ]; then\r\n            return 1\r\n        fi\r\n\r\n        for ((i=2; i*i<=num; i++)); do\r\n            if [ $((num%i)) -eq 0 ]; then\r\n                return 1\r\n            fi\r\n        done\r\n\r\n        return 0\r\n    }\r\n\r\n    # Function to print prime numbers within a range\r\n    print_primes() {\r\n        local start=$1\r\n        local end=$2\r\n\r\n        printf \"Prime numbers between %d and %d:\\n\" \"$start\" \"$end\"\r\n        for ((num=start; num<=end; num++)); do\r\n            if is_prime \"$num\"; then\r\n                echo \"$num\"\r\n            fi\r\n        done\r\n    }\r\n\r\n    # Main script\r\n    start_num=3\r\n    end_num=90\r\n\r\n    print_primes \"$start_num\" \"$end_num\"\r\n

#!/bin/bash
# Function to check if a number is prime
is_prime() {                            
    local num=$1
    if [ $num -lt 2 ]; then
        return 1
    fi          
      
    for ((i=2; i*i<=num; i++)); do
        if [ $((num%i)) -eq 0 ]; then
            return 1
        fi          
    done
        
    return 0
}           
 
# Function to print prime numbers within a range
print_primes() {
    local start=$1
    local end=$2
                
    printf "Prime numbers between %d and %d:\n" "$start" "$end"
    for ((num=start; num<=end; num++)); do
        if is_prime "$num"; then
            echo "$num"
        fi             
    done
}       
 
# Main script
start_num=3
end_num=90
          
print_primes "$start_num" "$end_num"
