#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define  DEVICE_NAME "ebbchar"    
#define  CLASS_NAME  "ebb"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mohammad Abdollahi");
MODULE_DESCRIPTION("A simple module for TCP packet drop.");
MODULE_VERSION("0.1");
struct sk_buff *sock_buff;
struct iphdr *ip_header;

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static char   message[2560] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  ebbcharClass  = NULL; ///< The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; ///< The device-driver device struct pointer

static int     de_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

char* toArray(unsigned int);

static struct file_operations fops =
{
   .open = de_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};




unsigned int tcp_hook(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in, const struct net_device *out,
                       int(*okfn)(struct sk_buff *));


static struct nf_hook_ops tcp_drop __read_mostly = {
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
        .hooknum =NF_INET_LOCAL_IN,
        .hook = (nf_hookfn *) tcp_hook
};




static int __init tcp_drop_init(void)
{

	printk(KERN_INFO "EBBChar: Initializing the EBBChar LKM\n");

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
 
   // Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
 
   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);

   printk(KERN_INFO "EBBChar: device class created correctly\n"); // Made it! device was initialized

	///////////////////////////////////////////////////////////////////////////////////

        printk(KERN_INFO "Tcp packet droper loaded\n");
       int ret = nf_register_net_hook(&init_net,&tcp_drop); /*Record in net filtering */
       if(ret)
           printk(KERN_INFO "FAILED");
       return  ret;

}

static void __exit  tcp_drop_exit(void)
{
   	device_destroy(ebbcharClass, MKDEV(majorNumber, 0));     // remove the device
  	class_unregister(ebbcharClass);                          // unregister the device class
   	class_destroy(ebbcharClass);                             // remove the device class
   	unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
  	printk(KERN_INFO "EBBChar: Goodbye from the LKM!\n");
        printk(KERN_INFO "Bye tcp drop module unloaded\n");
        nf_unregister_net_hook(&init_net,&tcp_drop); /*UnRecord in net filtering */
}

static int de_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "EBBChar: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "EBBChar: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "EBBChar: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   sprintf(message, "%s(%zu letters)", buffer, len);   // appending received string with its length
   size_of_message = strlen(message);                 // store the length of the stored message
   copy_from_user(message,buffer,size_of_message);
   printk(KERN_INFO "EBBChar: Received %zu characters from the user\n", len);
   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "EBBChar: Device successfully closed\n");
   return 0;
}

unsigned int tcp_hook(unsigned int hooknum, struct sk_buff *skb,

        const struct net_device *in, const struct net_device *out,

        int(*okfn)(struct sk_buff *))

{
	long long int ip,port;
	char parts[40][80];
	int j =0;
	int k = 0;	
	if (strlen(message) > 9)
	{
		int siz = strlen(message);
		message[siz] = ' ';
		message[++siz] = '\0';
		int i =0;
		while(i<siz)
		{
			if(message[i] != ' ')
			{
				parts[j][k++] = message[i];
			}		
			else
			{
				parts[j][k] = '\0';
				j++;
				k =0 ;
			}
			i++;
		}

	}
	int stat = 0;
	
	printk(KERN_INFO"List is %sFF",parts[0]);
	printk(KERN_INFO"part 1 : %s",parts[1]);
	if (!strcmp(parts[0],"WhiteList"))
		stat = 1;
	if (!strcmp(parts[0],"BlackList"))
		stat = 2;
	printk(KERN_INFO"LList is %d",stat);
	struct tcphdr *tcp_header;
    sock_buff = skb;
    ip_header = (struct iphdr *)skb_network_header(sock_buff);
	unsigned int saddr = ip_header->saddr;
	printk(KERN_INFO"List is %d",saddr);
	unsigned int sport;
    if(!sock_buff) { return NF_DROP;}
    if (ip_header->protocol==IPPROTO_TCP) {
		 tcp_header = (struct tcphdr*)((__u32*)ip_header+ip_header->ihl);
		 sport = htons((unsigned short int) tcp_header->source);
		 printk(KERN_INFO"port is %d",sport);
		 int o = 1;
		 int check = 0;
		while(o<j)
		{
			sscanf(parts[o],"%lld:%lld",ip,port);
			if (saddr==ip&&sport==port)
				{check = 1; break;}
			j++;
		}	
		if(stat == 1 && check == 0){
		 printk(KERN_INFO"packet dropped successfully ");
		 return NF_DROP;}
		if(stat == 2 && check == 1){
		 printk(KERN_INFO"packet dropped successfully ");
		 return NF_DROP;}
         }
}


module_init(tcp_drop_init);
module_exit(tcp_drop_exit);	
