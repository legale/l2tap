#include <linux/module.h>

#include <linux/netdevice.h>

#include <linux/etherdevice.h>

#include <linux/skbuff.h>

#include <linux/in.h>

#include <linux/inet.h>

#include <linux/net.h>

#include <linux/socket.h>

#include <linux/udp.h>

#include <net/sock.h>

#include <net/udp_tunnel.h>

#include <net/rtnetlink.h>

#include <linux/kobject.h>

#define DRV_NAME "l2tap"
#define MAX_UDP_PAYLOAD 1500

enum {
  L2TAP_ATTR_UNSPEC,
  L2TAP_ATTR_LOCAL_IP,
  L2TAP_ATTR_LOCAL_PORT,
  L2TAP_ATTR_REMOTE_IP,
  L2TAP_ATTR_REMOTE_PORT,
  __L2TAP_ATTR_MAX,
};
#define L2TAP_ATTR_MAX (__L2TAP_ATTR_MAX - 1)

static const struct nla_policy l2tap_policy[L2TAP_ATTR_MAX + 1] = {
    [L2TAP_ATTR_LOCAL_IP] = {.type = NLA_U32},
    [L2TAP_ATTR_LOCAL_PORT] = {.type = NLA_U16},
    [L2TAP_ATTR_REMOTE_IP] = {.type = NLA_U32},
    [L2TAP_ATTR_REMOTE_PORT] = {.type = NLA_U16},
};

struct l2tap_priv {
  struct net_device *dev;
  struct socket *udp_sock;
  __be32 local_ip;
  __be16 local_port;
  __be32 remote_ip;
  __be16 remote_port;
};

static struct rtnl_link_ops l2tap_link_ops;
static struct kobject *l2tap_kobj;

static int udp_tunnel_init(struct l2tap_priv *priv);

static char local_ip[16] = "172.16.133.2";
static char remote_ip[16] = "10.241.200.53";
static int local_port = 5555;
static int remote_port = 5556;

static ssize_t local_ip_show(struct kobject *kobj, struct kobj_attribute *attr,
                             char *buf) {
  return sprintf(buf, "%s", local_ip);
}

static ssize_t local_ip_store(struct kobject *kobj, struct kobj_attribute *attr,
                              const char *buf, size_t count) {
  snprintf(local_ip, sizeof(local_ip), "%s", buf);
  return count;
}

static ssize_t remote_ip_show(struct kobject *kobj, struct kobj_attribute *attr,
                              char *buf) {
  return sprintf(buf, "%s", remote_ip);
}

static ssize_t remote_ip_store(struct kobject *kobj,
                               struct kobj_attribute *attr, const char *buf,
                               size_t count) {
  snprintf(remote_ip, sizeof(remote_ip), "%s", buf);
  return count;
}

static ssize_t local_port_show(struct kobject *kobj,
                               struct kobj_attribute *attr, char *buf) {
  return sprintf(buf, "%d\n", local_port);
}

static ssize_t local_port_store(struct kobject *kobj,
                                struct kobj_attribute *attr, const char *buf,
                                size_t count) {
  int ret = kstrtoint(buf, 10, &local_port);
  if (ret < 0)
    return ret;
  return count;
}

static ssize_t remote_port_store(struct kobject *kobj,
                                 struct kobj_attribute *attr, const char *buf,
                                 size_t count) {
  int ret = kstrtoint(buf, 10, &remote_port);
  if (ret < 0)
    return ret;
  return count;
}

static ssize_t remote_port_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf) {
  return sprintf(buf, "%d\n", remote_port);
}

static struct kobj_attribute local_ip_attr =
    __ATTR(local_ip, 0660, local_ip_show, local_ip_store);
static struct kobj_attribute remote_ip_attr =
    __ATTR(remote_ip, 0660, remote_ip_show, remote_ip_store);
static struct kobj_attribute local_port_attr =
    __ATTR(local_port, 0660, local_port_show, local_port_store);
static struct kobj_attribute remote_port_attr =
    __ATTR(remote_port, 0660, remote_port_show, remote_port_store);

static void udp_receive(struct sock *sk) {
  struct sk_buff *skb;
  struct msghdr msg = {};
  struct kvec iov;
  int len;
  unsigned char buf[MAX_UDP_PAYLOAD]; // Изменено на unsigned char
  struct l2tap_priv *priv = (struct l2tap_priv *)sk->sk_user_data;
  struct ethhdr *eth;

  if (!priv || !priv->dev) {
    printk(KERN_ERR "%s: Invalid private structure or net_device.\n", DRV_NAME);
    return;
  }

  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  while (true) {
    len = kernel_recvmsg(priv->udp_sock, &msg, &iov, 1, MAX_UDP_PAYLOAD,
                         MSG_DONTWAIT | MSG_NOSIGNAL);

    if (len == -EAGAIN) {
      break;
    }

    if (len < 0) {
      printk(KERN_ERR "%s: Error receiving data, code: %d.\n", DRV_NAME, len);
      return;
    }

    // Проверка минимальной длины для Ethernet-заголовка
    if (len < sizeof(struct ethhdr)) {
      printk(KERN_ERR
             "%s: Received packet too small for Ethernet header, len = %d\n",
             DRV_NAME, len);
      return;
    }

    skb = dev_alloc_skb(len + 2);
    if (!skb) {
      printk(KERN_ERR "%s: Failed to allocate skb.\n", DRV_NAME);
      return;
    }

    skb_reserve(skb, 2);
    memcpy(skb_put(skb, len), buf, len);

    skb->dev = priv->dev;
    skb->protocol = eth_type_trans(skb, priv->dev);

    // Вывод первых байтов данных для отладки
    printk(KERN_INFO
           "%s: Raw packet data: %02x %02x %02x %02x %02x %02x %02x %02x\n",
           DRV_NAME, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6],
           buf[7]);

    // Извлечение Ethernet-заголовка
    eth = eth_hdr(skb);
    printk(KERN_INFO
           "%s: Received packet: Src MAC: %pM, Dest MAC: %pM, Protocol: 0x%x\n",
           DRV_NAME, eth->h_source, eth->h_dest, ntohs(eth->h_proto));

    // Проверка протокола и передача пакета в сетевой стек
    switch (skb->protocol) {
    case htons(ETH_P_IP):
    case htons(ETH_P_ARP):
    case htons(ETH_P_IPV6):
      netif_rx(skb);
      break;
    default:
      printk(KERN_WARNING "%s: Unsupported protocol: 0x%x. Dropping packet.\n",
             DRV_NAME, ntohs(skb->protocol));
      dev_kfree_skb(skb);
      break;
    }
  }
}

static netdev_tx_t l2tap_start_xmit(struct sk_buff *skb,
                                    struct net_device *dev) {
  struct msghdr msg = {};
  struct kvec iov;
  struct l2tap_priv *priv = netdev_priv(dev);
  struct sockaddr_in addr = {.sin_family = AF_INET,
                             .sin_port = priv->remote_port,
                             .sin_addr.s_addr = priv->remote_ip};
  int sent_bytes;
  struct ethhdr *eth = eth_hdr(skb);

  // Output the source and destination MAC addresses and protocol
  printk(KERN_INFO
         "%s: Sending packet: Src MAC: %pM, Dest MAC: %pM, Protocol: 0x%x\n",
         DRV_NAME, eth->h_source, eth->h_dest, ntohs(eth->h_proto));

  iov.iov_base = skb->data;
  iov.iov_len = skb->len;

  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);

  printk(
      KERN_INFO
      "%s: Before sending packet via UDP. Remote IP: %pI4, Remote Port: %u\n",
      DRV_NAME, &addr.sin_addr, ntohs(addr.sin_port));

  sent_bytes = kernel_sendmsg(priv->udp_sock, &msg, &iov, 1, skb->len);

  if (sent_bytes < 0) {
    printk(KERN_ERR "%s: Failed to send UDP packet. Error: %d\n", DRV_NAME,
           sent_bytes);
  } else {
    printk(KERN_INFO "%s: Packet sent via UDP. Sent Bytes: %d\n", DRV_NAME,
           sent_bytes);
  }

  dev_kfree_skb(skb);
  return NETDEV_TX_OK;
}

static int l2tap_up(struct net_device *dev) {
  struct l2tap_priv *priv = netdev_priv(dev);
  printk(KERN_INFO "%s: Interface up.\n", DRV_NAME);

  if (priv->udp_sock) {
    printk(KERN_WARNING
           "%s: UDP socket already initialized. Releasing existing socket.\n",
           DRV_NAME);
    sock_release(priv->udp_sock);
    priv->udp_sock = NULL;
  }

  if (udp_tunnel_init(priv) < 0) {
    printk(KERN_ERR "%s: Failed to initialize UDP tunnel.\n", DRV_NAME);
    return -1;
  }

  printk(KERN_INFO "%s: UDP tunnel successfully initialized.\n", DRV_NAME);
  netif_start_queue(dev);
  return 0;
}

static int l2tap_down(struct net_device *dev) {
  struct l2tap_priv *priv = netdev_priv(dev);

  printk(KERN_INFO "%s: Interface stopped.\n", DRV_NAME);

  if (!priv) {
    printk(KERN_ERR "%s: l2tap_stop called with null priv.\n", DRV_NAME);
    return -EINVAL;
  }

  if (priv->udp_sock) {
    printk(KERN_INFO "%s: Releasing UDP socket.\n", DRV_NAME);
    sock_release(priv->udp_sock);
    priv->udp_sock = NULL;
  } else {
    printk(KERN_WARNING "%s: UDP socket is already NULL.\n", DRV_NAME);
  }

  // Остановка очереди на отправку пакетов
  netif_stop_queue(dev);

  return 0;
}

static int l2tap_set_mac_address(struct net_device *dev, void *addr) {
  struct sockaddr *sockaddr = addr;

  if (!is_valid_ether_addr(sockaddr->sa_data))
    return -EADDRNOTAVAIL;

  memcpy((void *)dev->dev_addr, (void *)sockaddr->sa_data, dev->addr_len);

  return 0;
}

static const struct net_device_ops l2tap_netdev_ops = {
    .ndo_open = l2tap_up,
    .ndo_stop = l2tap_down,
    .ndo_start_xmit = l2tap_start_xmit,
    .ndo_set_mac_address = l2tap_set_mac_address,
};

static void l2tap_setup(struct net_device *dev) {
  struct l2tap_priv *priv = netdev_priv(dev);

  printk(KERN_INFO "%s: Setting up the net device.\n", DRV_NAME);
  ether_setup(dev);
  dev->netdev_ops = &l2tap_netdev_ops;
  dev->flags |= IFF_NOARP;
  dev->features |= NETIF_F_HW_CSUM;

  // Присваиваем случайный MAC-адрес
  eth_hw_addr_random(dev);

  priv->dev = dev;
}

static int l2tap_newlink(struct net *net, struct net_device *dev,
                         struct nlattr *tb[], struct nlattr *data[],
                         struct netlink_ext_ack *extack) {
  struct l2tap_priv *priv = netdev_priv(dev);

  printk(KERN_INFO "%s: New link creation initiated.\n", DRV_NAME);

  // global sysfs params
  priv->local_ip = in_aton(local_ip);
  priv->local_port = htons(local_port);
  priv->remote_ip = in_aton(remote_ip);
  priv->remote_port = htons(remote_port);

  printk(KERN_INFO "%s: Registering net device.\n", DRV_NAME);
  int ret = register_netdevice(dev);
  printk(KERN_INFO "%s: Net device registered, result: %d.\n", DRV_NAME, ret);

  return ret;
}

static void l2tap_dellink(struct net_device *dev, struct list_head *head) {
  struct l2tap_priv *priv;

  if (!dev) {
    printk(KERN_ERR "%s: l2tap_dellink called with null dev.\n", DRV_NAME);
    return;
  }

  priv = netdev_priv(dev);
  if (!priv) {
    printk(KERN_ERR "%s: l2tap_dellink called with null priv.\n", DRV_NAME);
    return;
  }

  printk(KERN_INFO "%s: Link deletion initiated for device %s.\n", DRV_NAME,
         dev->name);

  if (priv->udp_sock) {
    printk(KERN_INFO "%s: Releasing UDP socket.\n", DRV_NAME);
    sock_release(priv->udp_sock);
    priv->udp_sock = NULL; // Ensure it's set to NULL after release
  } else {
    printk(KERN_WARNING "%s: UDP socket is already NULL.\n", DRV_NAME);
  }

  // Ensure net_device is still valid before trying to unregister
  if (!head) {
    printk(KERN_ERR "%s: head is NULL in l2tap_dellink.\n", DRV_NAME);
    return;
  }

  printk(KERN_INFO "%s: Before calling unregister_netdevice_queue.\n",
         DRV_NAME);
  unregister_netdevice_queue(dev, head);
  printk(KERN_INFO "%s: After calling unregister_netdevice_queue.\n", DRV_NAME);
}

static int udp_tunnel_init(struct l2tap_priv *priv) {
  struct sockaddr_in addr;
  int ret;

  printk(KERN_INFO "%s: Creating UDP socket.\n", DRV_NAME);
  ret = sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &priv->udp_sock);
  if (ret < 0) {
    printk(KERN_ERR "%s: Failed to create UDP socket, error: %d\n", DRV_NAME,
           ret);
    return ret;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(local_port);
  addr.sin_addr.s_addr = in_aton(local_ip);

  printk(KERN_INFO "%s: Binding UDP socket to IP %pI4, port %d.\n", DRV_NAME,
         &addr.sin_addr, ntohs(addr.sin_port));
  ret = priv->udp_sock->ops->bind(priv->udp_sock, (struct sockaddr *)&addr,
                                  sizeof(addr));
  if (ret < 0) {
    printk(KERN_ERR "%s: Failed to bind UDP socket, error: %d\n", DRV_NAME,
           ret);
    sock_release(priv->udp_sock);
    return ret;
  }

  priv->udp_sock->sk->sk_user_data = priv;
  priv->udp_sock->sk->sk_data_ready = udp_receive;

  printk(KERN_INFO "%s: UDP tunnel initialized on local IP %pI4, port %d\n",
         DRV_NAME, &addr.sin_addr, ntohs(addr.sin_port));
  return 0;
}

static int __init l2tap_init(void) {
  int ret;

  l2tap_link_ops.kind = "l2tap";
  l2tap_link_ops.setup = l2tap_setup;
  l2tap_link_ops.newlink = l2tap_newlink;
  l2tap_link_ops.dellink = l2tap_dellink;
  l2tap_link_ops.policy = l2tap_policy;

  rtnl_link_register(&l2tap_link_ops);

  l2tap_kobj = kobject_create_and_add("l2tap", kernel_kobj);
  if (!l2tap_kobj) {
    printk(KERN_ERR "%s: Failed to create sysfs kobject.\n", DRV_NAME);
    return -ENOMEM;
  }

  ret = sysfs_create_file(l2tap_kobj, &local_ip_attr.attr);
  ret |= sysfs_create_file(l2tap_kobj, &remote_ip_attr.attr);
  ret |= sysfs_create_file(l2tap_kobj, &local_port_attr.attr);
  ret |= sysfs_create_file(l2tap_kobj, &remote_port_attr.attr);

  if (ret) {
    kobject_put(l2tap_kobj);
    printk(KERN_ERR "%s: Failed to create sysfs files.\n", DRV_NAME);
    return ret;
  }

  printk(KERN_INFO "%s: Module loaded.\n", DRV_NAME);
  return 0;
}

static void __exit l2tap_exit(void) {
  kobject_put(l2tap_kobj);
  rtnl_link_unregister(&l2tap_link_ops);
  printk(KERN_INFO "%s: Module unloaded.\n", DRV_NAME);
}

module_init(l2tap_init);
module_exit(l2tap_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ruslan Isaev");
MODULE_DESCRIPTION("L2 tap network interface with UDP tunnel support");
