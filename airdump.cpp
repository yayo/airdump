/*
g++ -ggdb3 -Wall -Wextra airdump.cpp -pthread -lpcap -lncurses -lboost_date_time-mt
*/

#include <sys/types.h>
#include <sys/event.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <ncurses.h>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <boost/assign.hpp>
#include <boost/format.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>

#define TITLE_PRE "Time         Bssid        beacoN PoW "
#define TITLE_CHANNELS "Channels"
#define TITLE_ESSID "Essid"
#define TITLE_SECURITY "Security"


struct beacon
{bpf_timeval ts;
 size_t count;
 int8_t power;
 int8_t power_max;
 std::map<int16_t,uint8_t> channel;
 std::string essid;
 uint16_t security;
 struct
  {std::string channel;
   std::string security;
  }cache;
};

std::ostream& operator<<(std::ostream &os,const struct beacon &b)
 {os<<"[\""
<<b.essid
<<"\",\""
<<boost::posix_time::to_iso_string(boost::posix_time::from_time_t(b.ts.tv_sec))
<<'.'
<<boost::format("%|1$06u|")%b.ts.tv_usec
<<"\","<<b.count
<<','<<(int16_t)b.power
<<','<<(int16_t)b.power_max
<<",{";
 std::map<int16_t,uint8_t>::const_iterator i;
 for(i=b.channel.begin();b.channel.end()!=i;)
  {os<<'\"'<<i->first<<"\":"<<(uint16_t)i->second;
   if(b.channel.end()!=++i) os<<',';
  }
os<<"},\""
<<b.cache.security
<<"\"]";
  
  return(os);
 }

typedef std::map<uint64_t,beacon> aps_t;

struct aps_sort_t
{static std::string o;
 const aps_t::const_iterator i;
 aps_sort_t(const aps_t::const_iterator i) : i(i) {}
 bool operator<(const aps_sort_t &a) const 
  {size_t s;
   for(s=0;s<o.size();s++)
    switch(o[s])
     {case 't':
       if(i->second.ts.tv_sec<a.i->second.ts.tv_sec) return(true);
       else if(i->second.ts.tv_sec>a.i->second.ts.tv_sec) return(false);
       else if(i->second.ts.tv_usec<a.i->second.ts.tv_usec) return(true);
       else if(i->second.ts.tv_usec>a.i->second.ts.tv_usec) return(false);
       else continue;
      case 'T':
       if(i->second.ts.tv_sec>a.i->second.ts.tv_sec) return(true);
       else if(i->second.ts.tv_sec<a.i->second.ts.tv_sec) return(false);
       else if(i->second.ts.tv_usec>a.i->second.ts.tv_usec) return(true);
       else if(i->second.ts.tv_usec<a.i->second.ts.tv_usec) return(false);
       else continue;
      case 'n':
       if(i->second.count<a.i->second.count) return(true);
       else if(i->second.count>a.i->second.count) return(false);
       else continue;
      case 'N':
       if(i->second.count>a.i->second.count) return(true);
       else if(i->second.count<a.i->second.count) return(false);
       else continue;
      case 'c':
       if(i->second.channel<a.i->second.channel) return(true);
       else if(i->second.channel>a.i->second.channel) return(false);
       else continue;
      case 'C':
       if(i->second.channel>a.i->second.channel) return(true);
       else if(i->second.channel<a.i->second.channel) return(false);
       else continue;
      case 'p':
       if(i->second.power<a.i->second.power) return(true);
       else if(i->second.power>a.i->second.power) return(false);
       else continue;
      case 'P':
       if(i->second.power>a.i->second.power) return(true);
       else if(i->second.power<a.i->second.power) return(false);
       else continue;
      case 'w':
       if(i->second.power_max<a.i->second.power_max) return(true);
       else if(i->second.power_max>a.i->second.power_max) return(false);
       else continue;
      case 'W':
       if(i->second.power_max>a.i->second.power_max) return(true);
       else if(i->second.power_max<a.i->second.power_max) return(false);
       else continue;
      case 'e':
       if(i->second.essid<a.i->second.essid) return(true);
       else if(i->second.essid>a.i->second.essid) return(false);
       else continue;
      case 'E':
       if(i->second.essid>a.i->second.essid) return(true);
       else if(i->second.essid<a.i->second.essid) return(false);
       else continue;
      case 's':
       if(i->second.security<a.i->second.security) return(true);
       else if(i->second.security>a.i->second.security) return(false);
       else continue;
      case 'S':
       if(i->second.security>a.i->second.security) return(true);
       else if(i->second.security<a.i->second.security) return(false);
       else continue;
      case 'B':
       return(i->first>a.i->first);
      case 'b':
      default:
       return(i->first<a.i->first);
     }
   return(true);
  }
};
std::string aps_sort_t::o;


struct scan_t
{aps_t *aps;
 size_t max_length_channel;
 size_t max_length_essid;
 size_t max_length_security;
 size_t start_COL;
 size_t start_LINE;
 bool nonblock;
 bool power_max;
 void (*out)(const std::set<aps_sort_t>&,const scan_t*);
 std::ostream *file;
};

#define IEEE80211_CHAN_2GHZ     0x0080  /* 2 GHz spectrum channel */
#define IEEE80211_CHAN_5GHZ     0x0100  /* 5 GHz spectrum channel */

uint16_t ieee80211_any2ieee(uint16_t freq, uint16_t flags)
{
        if (flags & IEEE80211_CHAN_2GHZ) {
                if (freq == 2484)
                        return 14;
                if (freq < 2484)
                        return (freq - 2407) / 5;
                else
                        return 15 + ((freq - 2512) / 20);
        } else if (flags & IEEE80211_CHAN_5GHZ) {
                return (freq - 5000) / 5;
        } else {
                /* Assume channel is already an IEEE number */
                return (freq);
        }
}

enum
{CHANNEL_FROM_BEACON=0,
 CHANNEL_FROM_RADIOTAP=1
};

const std::string channel2string(const std::map<int16_t,uint8_t> &c)
{std::string channelB,channelR;
 std::map<int16_t,uint8_t>::const_iterator i;
 bool channel_from_beacon=false;
 for(i=c.begin();i!=c.end();i++)
  {const uint8_t &channel_source=i->second;
   switch(channel_source)
    {case CHANNEL_FROM_BEACON:
      if(false==channel_from_beacon) channel_from_beacon=true;
      //else break; //assert(false==channel_from_beacon);
      channelB+=(boost::format("%|1$d|,")%i->first).str();
      break;
     case CHANNEL_FROM_RADIOTAP:
      channelR+=(boost::format("%|1$d|,")%i->first).str();
      break;
     default:
      assert(CHANNEL_FROM_BEACON==channel_source||CHANNEL_FROM_RADIOTAP==channel_source);
      break;
    }
  }
 assert(true==channel_from_beacon);
 channelB[channelB.size()-1]=':';
 channelB+=channelR;
 if(2<=channelB.size()) channelB.resize(channelB.size()-1);
 return(channelB);
}

enum
{STD_OPN   =0x0000,
 STD_WEP   =0x4000,
 STD_WPA   =0x8000,
 STD_WPA2  =0xC000,
 AUTH_OPN  =0x0800,
 AUTH_PSK  =0x1000,
 AUTH_MGT  =0x2000,
 ENC_WEP   =0x0020,
 ENC_TKIP  =0x0040,
 ENC_WRAP  =0x0080,
 ENC_CCMP  =0x0100,
 ENC_WEP40 =0x0200,
 ENC_WEP104=0x0400
};

const std::map<std::string,uint16_t> string2security=boost::assign::map_list_of
("OPN"   ,0x0000)
("WEP"   ,0x4000)
("WPA"   ,0x8000)
("WPA2"  ,0xC000)
("aOPN"  ,0x0800)
("PSK"   ,0x1000)
("MGT"   ,0x2000)
("eWEP"  ,0x0020)
("TKIP"  ,0x0040)
("WRAP"  ,0x0080)
("CCMP"  ,0x0100)
("WEP40" ,0x0200)
("WEP104",0x0400);

const std::string security2string(uint16_t security)
{static const char *security_names_STD[]={"OPN ","WEP ","WPA ","WPA2 "};
 static const char *security_names[]={"MGT ","PSK ","aOPN ","WEP104 ","WEP40 ","CCMP ","WRAP ","TKIP ","eWEP "};
 std::string s(security_names_STD[security>>14]);
 uint8_t i;
 for(i=0;i<sizeof(security_names);i++,security<<=1)
  if(0x2000&security) s+=security_names[i];
 s.resize(s.size()-1);
 return(s);
}

void parse_security(uint16_t *security,uint8_t *p,uint8_t offset) /* TODO web | PIN login */
{
 *security &=~(ENC_WEP);
 uint32_t numuni  = p[8+offset] + (p[9+offset]<<8);
 uint32_t numauth = p[(10+offset) + 4*numuni] + (p[(11+offset) + 4*numuni]<<8);
 p += (10+offset);
 uint32_t i;
                 for(i=0; i<numuni; i++)
                {
                    switch(p[i*4+3])
                    {
                    case 0x01:
                        *security |= ENC_WEP;
                        break;
                    case 0x02:
                        *security |= ENC_TKIP;
                        break;
                    case 0x03:
                        *security |= ENC_WRAP;
                        break;
                    case 0x04:
                        *security |= ENC_CCMP;
                        break;
                    case 0x05:
                        *security |= ENC_WEP104;
                        break;
                    default:
                        break;
                    }
                }
                p += 2+4*numuni;

                for(i=0; i<numauth; i++)
                {
                    switch(p[i*4+3])
                    {
                    case 0x01:
                        *security |= AUTH_MGT;
                        break;
                    case 0x02:
                        *security |= AUTH_PSK;
                        break;
                    default:
                        break;
                    }
                }


}

enum ieee80211_radiotap_type {
        IEEE80211_RADIOTAP_TSFT = 0,
        IEEE80211_RADIOTAP_FLAGS = 1,
        IEEE80211_RADIOTAP_RATE = 2,
        IEEE80211_RADIOTAP_CHANNEL = 3,
        IEEE80211_RADIOTAP_FHSS = 4,
        IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
        IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
        IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
        IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
        IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
        IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
        IEEE80211_RADIOTAP_ANTENNA = 11,
        IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
        IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
        IEEE80211_RADIOTAP_FCS = 14,
        IEEE80211_RADIOTAP_HWQUEUE = 15,
        IEEE80211_RADIOTAP_RSSI = 16,
        IEEE80211_RADIOTAP_EXT = 31
};

bool essid_escaped(std::string &e)
{bool utf8_invalid=false;
 std::string utf8;
 std::string hex("0x");
 size_t i;
 for(i=0;i<e.size();)
  {
   size_t n;
   utf8+=e[i];
   hex+=(boost::format("%|1$02X|")%(uint16_t)e[i]).str();
   if(0x00==(0x80&e[i]))
    {switch(e[i])
      {case '\x00':
        utf8_invalid=true;
        break;
       case '"':
        utf8+='\\';
        break;
      }
     n=0;
    }
   else if(0xC0==(0xE0&e[i])) {n=1; }
   else if(0xE0==(0xF0&e[i])) {n=2; }
   else if(0xF0==(0xF8&e[i])) {n=3; }
   else if(0xF8==(0xFC&e[i])) {n=4; }
   else if(0xFC==(0xFE&e[i])) {n=5; }
   else
    {utf8_invalid=true;
     n=0;
    }
   i++;
   size_t c;
   for(c=0;c<n;c++)
    {if(e.size()<=i+c)
      {utf8_invalid=true;
       break;
      }
     else
      {if(0x80!=(0xC0&e[i+c]))
        {utf8_invalid=true;
        }
       utf8+=e[i+c];
       hex+=(boost::format("%|1$02X|")%(uint16_t)e[i+c]).str();
      }
    }
   i+=n;
  }
 e=utf8_invalid?hex:utf8;
 return(utf8_invalid);
}

#define	IEEE80211_NWID_LEN 32
#define ESSID_NOT_FOUND "<*?NULL?*>"

void parse(uint8_t *aps0,const struct pcap_pkthdr *h,const uint8_t *p)
{
 scan_t *aps1=(scan_t*)aps0;
 uint16_t radiotap_len=*(uint16_t*)(p+2);
 uint32_t radiotap_present=*(uint16_t*)(p+4);

 const uint8_t *p1=p+8;
 #define RADIOTAP(_x) (radiotap_present&(1<<IEEE80211_RADIOTAP_##_x))
 if(RADIOTAP(TSFT)) p1+=8; /* TODO card => radiotap parse once */
 if(RADIOTAP(FLAGS)) p1+=1;
 if(RADIOTAP(RATE)) p1+=1;

 std::string essid(ESSID_NOT_FOUND);
 std::map<int16_t,uint8_t> channel;
 aps_t::key_type mac= 0x0000FFFFFFFFFFFF & betoh64(*(aps_t::key_type*)(p+radiotap_len+10-(sizeof(aps_t::key_type)-6)));
 uint16_t security=0;
 if(0x10 & *(p+radiotap_len+34))
  security|=STD_WEP|ENC_WEP;
 else
  security|=STD_OPN;
 uint8_t *s=(uint8_t*)p+radiotap_len+36;
 for(;s+2<p+h->caplen&&s+2+s[1]<p+h->caplen;s+=2+s[1])
  {switch(s[0])
    {case 0x00:
      if(IEEE80211_NWID_LEN>=s[1])
       {
      if(0==s[1])
       {if(ESSID_NOT_FOUND==essid) essid.clear();
       }
      else
       {std::string essid1(s+2,s+2+s[1]); /* TODO IEEE ESSID specification*/
        if(essid_escaped(essid1)) /* size<=32 */
         {if(ESSID_NOT_FOUND==essid) essid=essid1;
         }
        else
         {essid=essid1;
         }
        if(essid.size()>aps1->max_length_essid) aps1->max_length_essid=essid.size();
        break;
// 40169F6C3F7A
// 0014BFAFF617 0027193B1C48
//passed      if(0==memcmp("\xD8\x5D\x4C\xD7\x5F\xBF",p+radiotap_len+10,6) && p+radiotap_len+36!=s && 0==memcmp("TP-LINK_D75FBF",p+radiotap_len+36+2,14) ) continue; essid=std::string(s+2,s+2+s[1]); 
//passed      if(0==memcmp("\xF0\x7D\x68\xF3\xAF\xA8",p+radiotap_len+10,6) && 9==essid.size() && 0==memcmp("\x00\x00\x00\x00\x00\x00\x00\x00\x00",essid.c_str(),9) ) essid="000000000";
//passed      if(0==memcmp("\xC8\x64\xC7\x1C\x38\x68",p+radiotap_len+10,6) && 6==essid.size() && 0==memcmp("\x00\x00\x00\x00\x00\x00",essid.c_str(),6) ) essid="000000";
/*
      if(p+radiotap_len+36!=s)
       {fprintf(stderr,"ERR: %08X\n",(uint32_t)(s-p));
for(s=(uint8_t*)p;s<p+h->caplen;s++)
 {fprintf(stdout,"%02X:",*s);
 }
fprintf(stderr,"\n");
        assert(0==1);

pthread_exit(0);
       }
*/
      }
      }
      break;
     case 0x03:
      if(1==s[1]){channel[s[2]]=CHANNEL_FROM_BEACON;}
      break;
     case 0x30:
      security|=STD_WPA2;
      parse_security(&security,s,0);
      break;
     case 0xDD:
      if(0==memcmp("\x00\x50\xF2\x01\x01\x00",s+2,6))
       {security&=~STD_WEP;
        security|=STD_WPA;
        parse_security(&security,s,4);
       }
      break;
    }
  }

 if(RADIOTAP(CHANNEL)) 
  {channel.insert(std::pair<int16_t,uint8_t>(ieee80211_any2ieee(*(uint16_t*)(p1),*(uint16_t*)(p1+2)),CHANNEL_FROM_RADIOTAP));
   p1+=4;
  }
 if(RADIOTAP(FHSS)) p1+=2;
 int8_t power=(RADIOTAP(DBM_ANTSIGNAL))?*(int8_t*)(p1):0;
 aps_t *aps=aps1->aps;
 aps_t::iterator i=aps->find(mac);
 if(aps->end()!=i)
  {i->second.ts=h->ts;
   i->second.count++;
   i->second.power=power;
   if(power>i->second.power_max) i->second.power_max=power;
   std::string e;
   {bool updated=false;
    std::map<int16_t,uint8_t>::iterator c;
    for(c=channel.begin();c!=channel.end();c++)
     {std::map<int16_t,uint8_t>::iterator n=i->second.channel.find(c->first);
      if(n==i->second.channel.end())
       {i->second.channel.insert(*c);
        updated=true;
       }
      else if(n->second>c->second)
       {n->second=c->second;
        updated=true;
       }
     }
    if(updated)
     {i->second.cache.channel=channel2string(i->second.channel);
      if(i->second.cache.channel.size()>aps1->max_length_channel) aps1->max_length_channel=i->second.cache.channel.size();
     }
   }
   if(!essid.empty()&&essid!=i->second.essid)
    {if(!i->second.essid.empty()) e+="Essid["+i->second.essid+':'+essid+']';
     i->second.essid=essid;
    }
   if(security!=i->second.security)
    {i->second.security=security;
     i->second.cache.security=security2string(security);
     if(i->second.cache.security.size()>aps1->max_length_security) aps1->max_length_security=i->second.cache.security.size();
     e+="Security["+(boost::format("%|1$04X|:%|2$04X|")%i->second.security%security).str()+"]";
    }
   if(!e.empty())
    {mvaddstr(LINES-1,0,("Error: "+(boost::format("%|1$012X| ") %i->first).str()+e).c_str());
     clrtoeol();
     refresh();
     exit(-1);
    }
  }
 else
  {struct beacon b={h->ts,1,power,power,channel,essid,security,{channel2string(channel),security2string(security)}};
   if(b.cache.channel.size()>aps1->max_length_channel) aps1->max_length_channel=b.cache.channel.size();
   if(b.cache.security.size()>aps1->max_length_security) aps1->max_length_security=b.cache.security.size();
   aps->insert(aps_t::value_type(mac,b));
  }
}



void writescreen(const std::set<aps_sort_t> &aps_sort,const scan_t* aps)
{static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
 pthread_mutex_lock(&lock);
 std::string fmt((boost::format("%%|3$-%|3$u|s| %%|2$-%|2$u|s| %%|1$-%|1$u|s|")%aps->max_length_security%aps->max_length_essid%aps->max_length_channel).str());
 mvaddstr(0,0,(boost::format(TITLE_PRE+fmt)% (TITLE_SECURITY+ (boost::format("#%|1$u|/%|2$u||%|3$s|") %(aps->start_LINE+1)%aps->aps->size()%aps_sort_t::o).str()) %TITLE_ESSID%TITLE_CHANNELS).str().substr(aps->start_COL,COLS).c_str());
 clrtoeol();
 size_t line;
 std::set<aps_sort_t>::const_iterator sort=aps_sort.begin();
 for(line=0;line<aps->start_LINE&&sort!=aps_sort.end();sort++,line++);
 for(line=1;line<(size_t)LINES&&sort!=aps_sort.end();sort++,line++)
  {const aps_t::const_iterator &i=sort->i;
   mvaddstr(line,0,(boost::format("%|8$-8s|.%|7$03u| %|6$012X| %|5$6lu| %|4$3d| "+fmt) %i->second.cache.security % (i->second.essid) % i->second.cache.channel %(int16_t)(aps->power_max?i->second.power_max:i->second.power) %(uint16_t)i->second.count %i->first %(i->second.ts.tv_usec/1000) %boost::posix_time::to_simple_string(boost::posix_time::from_time_t(i->second.ts.tv_sec).time_of_day())).str().substr(aps->start_COL,COLS).c_str());
   clrtoeol();
  }
 refresh();
 pthread_mutex_unlock(&lock);
}

void writefile(const std::set<aps_sort_t> &aps_sort,const scan_t* aps)
{aps->file->seekp(0);
 *(aps->file)<<"{\n";
 std::set<aps_sort_t>::const_iterator sort=aps_sort.begin();
 for(;sort!=aps_sort.end();)
  {const aps_t::const_iterator &i=sort->i;
   *(aps->file)<<'\"'<<(boost::format("%|1$012X|") %i->first)<<"\":"<<i->second;
   if(aps_sort.end()!=++sort) *(aps->file)<<",";
    *(aps->file)<<'\n';
  }
 *(aps->file)<<'}';
 aps->file->flush();
 ((scan_t*)aps)->out=writescreen;
}

void draw(const scan_t *aps)
{std::set<aps_sort_t> aps_sort;
 aps_t::const_iterator i=aps->aps->begin();
 for(;i!=aps->aps->end();i++) aps_sort.insert(i);
 aps->out(aps_sort,aps);
}

struct param /* TODO move into thread */
{pcap_t *pd;
 int fd;
 int kq;
 scan_t **aps;
 std::fstream *file;
};

void* scan(void *p0)
{const struct param *&p=(const struct param *&)p0;
//fprintf(stderr,"\n\nHERE: %016llX\n",11);
 aps_t aps0;
 scan_t aps={&aps0,sizeof(TITLE_CHANNELS)-1,sizeof(TITLE_ESSID)-1,sizeof(TITLE_SECURITY)-1,0,0,0,0,writescreen,p->file};
 if(NULL!=p->file)
  {boost::property_tree::ptree pt;
   boost::property_tree::json_parser::read_json(*(p->file),pt);
   boost::property_tree::ptree::const_iterator i;
   for(i=pt.begin();i!=pt.end();i++)
    {assert(12==i->first.size());
     aps_t::key_type bssid;
     assert(6==sscanf(i->first.c_str(),"%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",((uint8_t*)&bssid)+5,((uint8_t*)&bssid)+4,((uint8_t*)&bssid)+3,((uint8_t*)&bssid)+2,((uint8_t*)&bssid)+1,((uint8_t*)&bssid)+0)); /* TODO last invalid char should not be accepted ! */
     bssid&=0x0000FFFFFFFFFFFF;
     assert(aps0.end()==aps0.find(bssid));

     assert(7==i->second.size());
     boost::property_tree::ptree::const_iterator i2=i->second.begin();
     beacon b;

     assert(i2->first.empty());
     b.essid=(i2++)->second.data();
     if(b.essid.size()>aps.max_length_essid) aps.max_length_essid=b.essid.size();

     assert(i2->first.empty()&&22==i2->second.data().size()&&'T'==i2->second.data()[8]&&'.'==i2->second.data()[15]);
     b.ts.tv_sec=(boost::posix_time::from_iso_string(i2->second.data().substr(0,15))-boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_seconds() ;
     b.ts.tv_usec=boost::lexical_cast<uint32_t>(i2->second.data().substr(16,6));
     i2++;

     assert(i2->first.empty());
     b.count=boost::lexical_cast<size_t>((i2++)->second.data()); /* TODO reset count */

     assert(i2->first.empty());
     b.power=boost::lexical_cast<int16_t>((i2++)->second.data());
     assert(i2->first.empty());
     b.power_max=boost::lexical_cast<int16_t>((i2++)->second.data());
     assert(b.power<=b.power_max); /* TODO reset power */

     assert(i2->first.empty()&&!i2->second.empty());
     boost::property_tree::ptree::const_iterator i3;
     bool channel_from_beacon=false;
     for(i3=i2->second.begin();i3!=i2->second.end();i3++)
      {uint8_t channel_source=boost::lexical_cast<uint16_t>(i3->second.data());
       switch(channel_source)
        {case CHANNEL_FROM_BEACON:
          if(false==channel_from_beacon) channel_from_beacon=true;
          break;
         case CHANNEL_FROM_RADIOTAP: break;
         default:
          assert(CHANNEL_FROM_BEACON==channel_source||CHANNEL_FROM_RADIOTAP==channel_source);
          break;
        }
       b.channel.insert(std::pair<int16_t,uint8_t>(boost::lexical_cast<int16_t>(i3->first),channel_source));
      }
     assert(true==channel_from_beacon);
     b.cache.channel=channel2string(b.channel);
     if(b.cache.channel.size()>aps.max_length_channel) aps.max_length_channel=b.cache.channel.size();
     i2++;

     assert(i2->first.empty());
     std::list<std::string> s;
     boost::algorithm::split(s,i2->second.data(),boost::is_any_of(" "));
     assert(1<=s.size());
     std::list<std::string>::const_iterator i4=s.begin();
     std::map<std::string,uint16_t>::const_iterator i5=string2security.find(*i4);
     assert(string2security.end()!=i5);
     b.security=i5->second;
     assert(0==(b.security&0x3FFF));
     for(i4++;s.end()!=i4;i4++)
      {i5=string2security.find(*i4);
       assert(string2security.end()!=i5);
       b.security|=i5->second;
      }
     b.cache.security=security2string(b.security);
     assert(i2->second.data()==b.cache.security);
     if(b.cache.security.size()>aps.max_length_security) aps.max_length_security=b.cache.security.size();
     aps0.insert(aps_t::value_type(bssid,b));
    }
  }

 *(p->aps)=&aps;
 struct kevent change;
 EV_SET(&change,p->fd,EVFILT_READ,EV_ADD|EV_ONESHOT,0,0,NULL);
 while(1)
  {
   if( (0!=aps.nonblock) && 1!=kevent(p->kq,&change,1,&change,1,NULL))
    {fprintf(stderr,"BAD2\n"); // TODO stderr view
     assert(0==1);
     return(NULL);
    }
   else
    {pcap_dispatch(p->pd,0,parse,(uint8_t*)(&aps)); /* TODO endure pcap_close */
     draw(&aps);
    }
  }
}

int main(int argc,char *argv[])
{

 if(2>argc) /* TODO boost/program_options */
  {return(-1);
  }
 else /* TODO return(rt); */
  {char ebuf[PCAP_ERRBUF_SIZE];
   param p;
   p.pd=pcap_open_live(argv[1],65535,1,0,ebuf);
   if(NULL==p.pd)
    {fprintf(stderr,"%s\n",ebuf);
     return(-1);
    }
   else
    {std::cerr<<"Change interface "<<argv[1]<<" data link type from "<<pcap_datalink_val_to_name(pcap_datalink(p.pd))<<" to "; /* check dev link type like tcpdump -i interface -L */
     if(0!=pcap_set_datalink(p.pd,pcap_datalink_name_to_val("IEEE802_11_RADIO")))
      {fprintf(stderr,"Error!\n");
       return(-2);
      }
     else
      {std::cerr<<pcap_datalink_val_to_name(pcap_datalink(p.pd))<<'\n';
       std::string f1("4<len and (ether[3]<<8)+ether[2]+38<len and (0x80=ether[(ether[3]<<8)+ether[2]]&0xFC or 0x50=ether[(ether[3]<<8)+ether[2]]&0xFC) and ether dst FF:FF:FF:FF:FF:FF "); // IEEE80211_FC0_TYPE_MGT && ( IEEE80211_FC0_SUBTYPE_BEACON || IEEE80211_FC0_SUBTYPE_PROBE_RESP )
       if(3==argc) (f1+="and ether src ")+=argv[2];
       std::cerr<<"Filter: "<<f1<<'\n';
       struct bpf_program fp;
       if(0!=pcap_compile(p.pd,&fp,(char*)f1.c_str(),1,0))
        {return(-1);
        }
       else
        {
         if(0!=pcap_setfilter(p.pd,&fp))
          {return(-1);
          }
         else
          {p.fd=pcap_fileno(p.pd);
           if(-1==p.fd)
            {return(-1);
            }
           else
            {
             if(0!=pcap_setnonblock(p.pd,0,ebuf))
              {fprintf(stderr,"BAD2: %s\n",ebuf);
               return(-1);
              }
             else
              {
               p.kq=kqueue();
               if(-1==p.kq)
                {return(-1);
                }
               else
                {pthread_t t;
                 pthread_attr_t a;
                 if(0!=pthread_attr_init(&a))
                   {return(-2);
                   }
                 else
                   {if(0!=pthread_attr_setdetachstate(&a,PTHREAD_CREATE_DETACHED))
                     {return(-1);
                     }
                    else
                     {std::fstream file("aps"); /* TODO multi aps input */ /* TODO merge aps files */
                      if(!file.good())
                       {std::cerr<<"Can not open file!\n";
                       }
                      else
                       {p.file=&file;
                        scan_t *aps=NULL;
                        p.aps=&aps;
                        initscr();
                        nonl();
                        curs_set(0);
                        raw();
                        keypad(stdscr,TRUE);
                        noecho();
                        if(0!=pthread_create(&t,&a,scan,&p))
                          {return(-1);
                          }
                        else
                         {
                          while(NULL==aps); // Wait scan() init it
                          aps_sort_t::o='b';
                          int c;
                          while('q'!=(c=getch()))
                          //while('q'!=(c=getchar()))
                           {assert(3<=LINES&&"TITLE+DISPLAY+PAGE");
                            switch(c)
                             {
                              case 't':
                              case 'b':
                              case 'n':
                              case 'c':
                              case 'p':
                              case 'w':
                              case 'e':
                              case 's':
                               if(c==aps_sort_t::o[0]) aps_sort_t::o[0]=toupper(c);
                               else if(toupper(c)==aps_sort_t::o[0]) aps_sort_t::o[0]=c;
                               else
                                {size_t i;
                                 i=aps_sort_t::o.find(c);
                                 if(aps_sort_t::o.size()>i) aps_sort_t::o.erase(i,1);
                                 else
                                  {c=toupper(c);
                                   i=aps_sort_t::o.find(c);
                                   if(aps_sort_t::o.size()>i) aps_sort_t::o.erase(i,1);
                                  }
                                 aps_sort_t::o=aps_sort_t::o.insert(0,1,c);
                                }
                               break;
                              case 'o':
                               if(0==aps->power_max) aps->power_max=1;
                               else aps->power_max=0;
                               break;
                              case KEY_RIGHT:
                               if(sizeof(TITLE_PRE)+aps->max_length_channel+aps->max_length_essid +aps->max_length_security+1>aps->start_COL+COLS) aps->start_COL++;
                               break;
                              case KEY_LEFT:
                               if(0!=aps->start_COL) aps->start_COL--;
                               break;
#define DISPLAY_LINES (LINES-1)
#define PAGE_MOVE (DISPLAY_LINES-1)
                              case KEY_DOWN:
                               if(aps->aps->size()>aps->start_LINE+DISPLAY_LINES) aps->start_LINE++;
                               break;
                              case KEY_UP:
                               if(0!=aps->start_LINE) aps->start_LINE--;
                               break;
                              case KEY_NPAGE:
                               if(aps->aps->size()>aps->start_LINE+DISPLAY_LINES+PAGE_MOVE) aps->start_LINE+=PAGE_MOVE;
                               else aps->start_LINE=aps->aps->size()>(size_t)DISPLAY_LINES?aps->aps->size()-DISPLAY_LINES:0;
                               break;
                              case KEY_PPAGE:
                               if((size_t)(PAGE_MOVE)<aps->start_LINE) aps->start_LINE-=PAGE_MOVE;
                               else aps->start_LINE=0;
                               break;
                              case KEY_END:
                               //aps->start_LINE=aps->aps->size()>(size_t)DISPLAY_LINES?aps->aps->size()-DISPLAY_LINES:0;
                               break;
                              case KEY_HOME:
                               //aps->start_LINE=0;
                               break;
                              case 'r':
                               //aps->nonblock=~(aps->nonblock); /* TODO Why */
                               if(0==aps->nonblock) aps->nonblock=1;
                               else aps->nonblock=0;
                               //pcap_setnonblock(p.pd,0/*aps->nonblock*/,ebuf);
                               break;
  /*
                              case 'z': // TODO debug stderr
                               def_prog_mode();
                               endwin();
                               break;
                              case 'x':
                               reset_prog_mode();
                               refresh();
                               break;
  */
                              case 'x':
         //    close(p.fd);
     //    pcap_freecode(&fp);
     pcap_close(p.pd);// p.pd=NULL;
                               break;
                              default:;
                               //fprintf(stderr,"%08X\n",c);
                             }
                            draw(aps);
                           }
                         }
                        endwin();
                        aps->out=writefile;
                        draw(aps);
                        file.close();
                       }
                     }
                    pthread_attr_destroy(&a);
                   }
                 close(p.kq);
                }
              }
             close(p.fd);
            }
          }
         pcap_freecode(&fp);
        }
      }
     pcap_close(p.pd);
     return(0);
    }
  }
}
