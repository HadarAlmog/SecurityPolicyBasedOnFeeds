import feedparser
import hashlib
import time
import xml.etree.ElementTree as ET

# Configurations
FEED_CONFIG_SYNTAX_FEED_NAME = 0
FEED_CONFIG_SYNTAX_FEED_LINK = 1
DEFAULT_INTERVAL = 30

###########################################################################################################################

class Aggregator:
    def __init__(self,feeds,interval):
        self.list_of_feeds=feeds
        self.uniq_indicators_from_all_feeds = [] #uniq
        self.interval = interval #in seconds


    def receive_indicators_from_all_feeds(self):
        self.uniq_indicators_from_all_feeds = []
        for f in self.list_of_feeds:
            f.receive_indicators_from_feed()
            for ind in f.get_indicators():
                #Make sure the same indicator was not added already, cannot use: "if ind not in self.indicators_from_all_feeds:" since need to compare only security related info
                if len(list(filter(ind.compare_to_indicator,self.uniq_indicators_from_all_feeds))) ==0:

                    self.uniq_indicators_from_all_feeds.append(ind)
        print ("Done getting all indicators. Got", len(self.uniq_indicators_from_all_feeds), "uniq indicators")


    def get_uniq_indicators_from_all_feeds(self):
        return self.uniq_indicators_from_all_feeds


    def generate_security_rules(self):
        print("Generating security policy.... TBD, for example:")
        print (map(lambda x: x.get_five_tuple() + x.get_signature(), self.get_uniq_indicators_from_all_feeds()))


    def install_feeds_policy(self):
        print ("Installing feed policy from", len(self.uniq_indicators_from_all_feeds),"indicators.... TBD")


###########################################################################################################################

class Feed:
    def __init__(self,name,link):
        print ("HADAR " , hash.digest_size)
        self.id = hashlib.sha224(link.encode('utf-8')).hexdigest() #TODO: generate a shorter ID
        self.name = name
        self.link = link
        self.last_com_time = None
        self.feed_indicators = []
        #self.interval = 0


    def __str__(self):
        return "Feed name: "+ self.name + "   Feed Link: " + self.link+ "   Feed ID: " + self.id


    def receive_indicators_from_feed(self):
        self.feed_indicators = []
        feed_response = feedparser.parse(self.link)
        self.last_com_time = time.localtime(time.time())

        #print ('Number of rules :', len(feed_response.entries))
        for i in (range(len(feed_response.entries))):
            #print (i, feed_response.entries[i])
            #print (feed_response.entries[i].link)
            indicator = Indicator(feed_response.entries[i],self.name)
            self.feed_indicators.append ( indicator )
        print("Done getting indicators from", self.name+". Got", len(self.feed_indicators), "indicators on",time.asctime(self.last_com_time))


    def get_indicators(self):
        return self.feed_indicators


###########################################################################################################################

class Indicator:
    def __init__(self,rss_entry,feed_name):
        self.orig_rss_entry = rss_entry

        self.id = hashlib.sha224(rss_entry.id.encode('utf-8')).hexdigest() #TODO: generate a shorter ID
        self.link = rss_entry.link
        self.creation_time = rss_entry.published
        self.description = rss_entry.title
        self.author = 'TBD'
        self.feed_name = feed_name
        #self.ttl = 0

        # TODO: get real security values from the feed server.
        # Currently, the code is manipulating the received data so it will fit the example, as follows:
        # If the published hour is not divided by 2 than consider this indicator as a 5-tuple, otherwise use it as a file md5
        # The 5-tuple data and the MD5 are currently generated yb manipulating 'published' value.
        self.is_5tuple = rss_entry.published_parsed[3]%2                     #TODO: same
        self.src_ip=str(self.is_5tuple * rss_entry.published_parsed[3])      #TODO: same
        self.src_port=str(self.is_5tuple * rss_entry.published_parsed[4])    #TODO: same
        self.dst_ip=str(self.is_5tuple * rss_entry.published_parsed[5])      #TODO: same
        self.dst_port=str(self.is_5tuple * rss_entry.published_parsed[1])    #TODO: same
        self.ip_protocol=str(self.is_5tuple * rss_entry.published_parsed[6]) #TODO: same
        self.md5 = str((self.is_5tuple+1)*rss_entry.published_parsed[5])     #TODO: same
        self.file_extension='pdf'

    def is_same_indicator(self,other_indicator):
        if self.is_5tuple and other_indicator.is_5tuple:
            if self.src_ip == other_indicator.src_ip and \
                self.src_port == other_indicator.src_port and \
                self.dst_ip == other_indicator.dst_ip and \
                self.dst_port == other_indicator.dst_port and \
                self.ip_protocol == other_indicator.ip_protocol:
                return True
        if not self.is_5tuple and not other_indicator.is_5tuple:
            if self.md5 == other_indicator.md5 and \
                self.file_extension == other_indicator.file_extension:
                return True

        return False


    def __str__(self):
        return " id:"+self.id+" creation_time: "+self.creation_time+" feed:"+self.feed_name+\
               " src_ip:"+self.src_ip+" src_port:"+self.src_port+" dst_ip:"+self.dst_ip+" dst_port:"+self.dst_port+" ip_proto:"+self.ip_protocol+\
               " md5:"+self.md5+" file extension:"+self.file_extension +\
               " description:"+self.description+" link: "+self.link


    def get_five_tuple(self):
        return "" if self.is_5tuple == 0 else "5-tuple: ("+self.src_ip + "," + self.src_port + "," + self.dst_ip + "," + self.dst_port + "," + self.ip_protocol+")" if self.is_5tuple==1 else ""


    def get_signature(self):
        return "" if self.is_5tuple == 1 else "File extension:"+self.file_extension+ ", MD5: "+self.md5

###########################################################################################################################


def init_feeds_and_aggregator():
    # TODO: Read from the config file!
    input_config = [ ["Feed-server-1","https://timesofindia.indiatimes.com/rssfeedstopstories.cms"] , ["Feed-server-2","https://timesofindia.indiatimes.com/rssfeedstopstories.cms"] ]
    interval = DEFAULT_INTERVAL

    tmp_feeds = []
    for i in range(len(input_config)):
        tmp_feeds.append( Feed(input_config[i][FEED_CONFIG_SYNTAX_FEED_NAME], input_config[i][FEED_CONFIG_SYNTAX_FEED_LINK]) )

    print (len(tmp_feeds ), "feeds configured:")
    for i in range(len(tmp_feeds )):
        print(i, ":    ", tmp_feeds [i])

    tmp_aggregator = Aggregator(tmp_feeds,interval)
    return tmp_aggregator


def main():
    print("\n\nInit....")
    aggregator = init_feeds_and_aggregator()

    while True:
        print("\n\nCommunicating with feed servers....")
        aggregator.receive_indicators_from_all_feeds()

        # print all aggregated indicators
        for i in aggregator.get_uniq_indicators_from_all_feeds():
            print(i)
            #print (i.orig_rss_entry)

        # Generate feeds policy and install it
        aggregator.generate_security_rules()
        aggregator.install_feeds_policy()

        print("\n\nsleeping",aggregator.interval,"seconds....")
        time.sleep(aggregator.interval)


if __name__=="__main__":
    main()