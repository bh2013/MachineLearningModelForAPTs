import unittest
import ReadData

class TestPacket(unittest.TestCase):
    def test_getInterfaces(self):
        
        interfaces = ReadData.getInterfaces()
        print(interfaces)
        for each in interfaces:
            if each == 'en0':
                self.assertTrue(True)
                
   
        

if __name__ == '__main__':
    unittest.main()