using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace HttpClientExtras
{
    public static class HttpContentExtensions
    {
        public static Task<T> ReadAsAsync<T>(this HttpContent content)
        {
            return content
                .ReadAsStreamAsync()
                .ContinueWith(stream =>
                                  {
                                      var ser = new XmlSerializer(typeof(T));
                                      var s = new StreamReader(stream.Result).ReadToEnd();
                                      var o = ser.Deserialize(new StringReader(s));
//                                      var o = ser.Deserialize(stream.Result);
                                      return (T)o;
                                  });
        }
    }
}
