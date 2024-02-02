namespace certreq
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Request r = new Request();
            string csr= r.GenerateCSR();
            Console.WriteLine(csr);
        }
    }
}
