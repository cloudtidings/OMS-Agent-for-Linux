require 'test/unit'

require_relative '../../../source/code/plugins/changetracking_lib'
require_relative 'omstestlib'

class ChangeTrackingTest < Test::Unit::TestCase

  def setup
    @package_xml_str = '<INSTANCE CLASSNAME="Inventory"><PROPERTY.ARRAY NAME="Instances" TYPE="string" EmbeddedObject="object"><VALUE.ARRAY><VALUE>&lt;INSTANCE CLASSNAME=&quot;MSFT_nxPackageResource&quot;&gt;&lt;PROPERTY NAME=&quot;Publisher&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;CentOS BuildSystem &amp;lt;http://bugs.centos.org&amp;gt;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;ReturnCode&quot; TYPE=&quot;uint32&quot;&gt;&lt;VALUE&gt;0&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Name&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;rsyslog&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;FilePath&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;PackageGroup&quot; TYPE=&quot;boolean&quot;&gt;&lt;VALUE&gt;false&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Installed&quot; TYPE=&quot;boolean&quot;&gt;&lt;VALUE&gt;true&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;InstalledOn&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;1445271183&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Version&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;7.4.7&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Ensure&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;present&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Architecture&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;x86_64&amp;#10;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Arguments&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;PackageManager&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;PackageDescription&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;Enhanced system logging and kernel message trapping daemon&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Size&quot; TYPE=&quot;uint32&quot;&gt;&lt;VALUE&gt;2033615&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;/INSTANCE&gt;</VALUE></VALUE.ARRAY></PROPERTY.ARRAY></INSTANCE>'
    @service_xml_str = '<INSTANCE CLASSNAME="Inventory"><PROPERTY.ARRAY NAME="Instances" TYPE="string" EmbeddedObject="object"><VALUE.ARRAY><VALUE>&lt;INSTANCE CLASSNAME=&quot;MSFT_nxServiceResource&quot;&gt;&lt;PROPERTY NAME=&quot;Publisher&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;(none)&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;ReturnCode&quot; TYPE=&quot;uint32&quot;&gt;&lt;VALUE&gt;0&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Name&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;omsagent&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;FilePath&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;PackageGroup&quot; TYPE=&quot;boolean&quot;&gt;&lt;VALUE&gt;false&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Installed&quot; TYPE=&quot;boolean&quot;&gt;&lt;VALUE&gt;true&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;InstalledOn&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;1458339065&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Version&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;1.1.0&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Ensure&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;present&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Architecture&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;x86_64&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Arguments&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;PackageManager&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;PackageDescription&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;Microsoft Operations Management Suite for UNIX/Linux agent&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Size&quot; TYPE=&quot;uint32&quot;&gt;&lt;VALUE&gt;38487871&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;/INSTANCE&gt;</VALUE></VALUE.ARRAY></PROPERTY.ARRAY></INSTANCE>'
    @fileInventory_xml_str = '<INSTANCE CLASSNAME="Inventory"><PROPERTY.ARRAY NAME="Instances" TYPE="string" EmbeddedObject="object"><VALUE.ARRAY><VALUE>&lt;INSTANCE CLASSNAME=&quot;MSFT_nxFileInventoryResource&quot;&gt;&lt;PROPERTY NAME=&quot;Group&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;root&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Checksum&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;1471727542&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;DestinationPath&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;/etc/yum.conf&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Mode&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;644&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;CreatedDate&quot; TYPE=&quot;datetime&quot;&gt;&lt;VALUE&gt;20160820211222.000000+300&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Owner&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;root&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Type&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;file&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;ModifiedDate&quot; TYPE=&quot;datetime&quot;&gt;&lt;VALUE&gt;20160820211222.000000+300&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;Contents&quot; TYPE=&quot;string&quot;&gt;&lt;VALUE&gt;&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;PROPERTY NAME=&quot;FileSize&quot; TYPE=&quot;uint64&quot;&gt;&lt;VALUE&gt;835&lt;/VALUE&gt;&lt;/PROPERTY&gt;&lt;/INSTANCE&gt;</VALUE></VALUE.ARRAY></PROPERTY.ARRAY></INSTANCE>'

    @packageinventoryPath = File.join(File.dirname(__FILE__), 'InventoryPackage.xml')
    @serviceinventoryPath = File.join(File.dirname(__FILE__), 'InventoryService.xml')
    @fileinventoryPath = File.join(File.dirname(__FILE__), 'InventoryFile.xml')
    ChangeTracking.prev_hash = nil
  end

  def teardown

  end

  def test_strToXML
    xml = ChangeTracking.strToXML(@service_xml_str)
    assert(xml.is_a?(REXML::Document), "Expected return type is REXML::Document")
  end

  def test_strToXML_fail
    assert_raise REXML::ParseException do
      ChangeTracking.strToXML("<<<<")
    end
  end

  def test_strToXML_file_inventory
    xml = ChangeTracking.strToXML(@fileInventory_xml_str)
    assert(xml.is_a?(REXML::Document), "Expected return type is REXML::Document")
  end

  def test_getInstancesXML
    xml = ChangeTracking.strToXML(@service_xml_str)
    assert(xml.root != nil, 'Failed find the root of the xml document')
    assert_equal("INSTANCE", xml.root.name)
    instances = ChangeTracking.getInstancesXML(xml)
    # puts ">>#{instances}<<"
    assert_equal(1, instances.size)
    assert_equal("INSTANCE", instances[0].name)
    assert_equal("MSFT_nxServiceResource", instances[0].attributes['CLASSNAME'])
  end

  def test_getInstancesXML_file_inventory
    xml = ChangeTracking.strToXML(@fileInventory_xml_str)
    assert(xml.root != nil, 'Failed find the root of the xml document')
    assert_equal("INSTANCE", xml.root.name)
    instances = ChangeTracking.getInstancesXML(xml)
    #puts ">>#{instances}<<"
    assert_equal(1, instances.size)
    assert_equal("INSTANCE", instances[0].name)
    assert_equal("MSFT_nxFileInventoryResource", instances[0].attributes['CLASSNAME'])
  end

  def test_serviceXMLtoHash
    instanceXMLstr = %{
      <INSTANCE CLASSNAME="MSFT_nxServiceResource">
        <PROPERTY NAME="Name" TYPE="string">
          <VALUE>iprdump</VALUE>
        </PROPERTY>
        <PROPERTY NAME="Runlevels" TYPE="string">
          <VALUE>2, 3, 4, 5</VALUE>
        </PROPERTY>
        <PROPERTY NAME="Enabled" TYPE="boolean">
          <VALUE>false</VALUE>
        </PROPERTY>
        <PROPERTY NAME="State" TYPE="string">
          <VALUE>stopped</VALUE>
        </PROPERTY>
        <PROPERTY NAME="Controller" TYPE="string">
          <VALUE>init</VALUE>
        </PROPERTY>
        <PROPERTY NAME="Path" TYPE="string">
          <VALUE>/etc/rc.d/init.d/iprdump</VALUE>
        </PROPERTY>
        <PROPERTY NAME="Description" TYPE="string">
          <VALUE>IBM Power RAID adapter dump utility</VALUE>
        </PROPERTY>
      </INSTANCE>
    }
    expectedHash = {
      "CollectionName"=> "iprdump",
      "Name"=> "iprdump",
      "Description"=> "IBM Power RAID adapter dump utility",
      "State"=> "stopped",
      "Path"=> "/etc/rc.d/init.d/iprdump",
      "Runlevels"=> "2, 3, 4, 5",
      "Enabled"=> "false",
      "Controller"=> "init"
    }
    instanceXML = ChangeTracking::strToXML(instanceXMLstr).root
    assert_equal("INSTANCE", instanceXML.name)
    assert_equal("MSFT_nxServiceResource", instanceXML.attributes['CLASSNAME'])
    instanceHash = ChangeTracking::serviceXMLtoHash(instanceXML)
    assert_equal(expectedHash, instanceHash)
  end

  def test_packageXMLtoHash
    instanceXMLstr = %{
      <INSTANCE CLASSNAME="MSFT_nxPackageResource">
          <PROPERTY NAME="Publisher" TYPE="string">
            <VALUE>MicrosoftPublisher</VALUE>
          </PROPERTY>
          <PROPERTY NAME="ReturnCode" TYPE="uint32">
            <VALUE>0</VALUE>
          </PROPERTY>
          <PROPERTY NAME="Name" TYPE="string">
            <VALUE>omsagent</VALUE>
          </PROPERTY>
          <PROPERTY NAME="FilePath" TYPE="string">
            <VALUE></VALUE>
          </PROPERTY>
          <PROPERTY NAME="PackageGroup" TYPE="boolean">
            <VALUE>false</VALUE>
          </PROPERTY>
          <PROPERTY NAME="Installed" TYPE="boolean">
            <VALUE>true</VALUE>
          </PROPERTY>
          <PROPERTY NAME="InstalledOn" TYPE="string">
            <VALUE>1458339065</VALUE>
          </PROPERTY>
          <PROPERTY NAME="Version" TYPE="string">
            <VALUE>1.1.0</VALUE>
          </PROPERTY>
          <PROPERTY NAME="Ensure" TYPE="string">
            <VALUE>present</VALUE>
          </PROPERTY>
          <PROPERTY NAME="Architecture" TYPE="string">
            <VALUE>x86_64</VALUE>
          </PROPERTY>
          <PROPERTY NAME="Arguments" TYPE="string">
            <VALUE></VALUE>
          </PROPERTY>
          <PROPERTY NAME="PackageManager" TYPE="string">
            <VALUE></VALUE>
          </PROPERTY>
          <PROPERTY NAME="PackageDescription" TYPE="string">
            <VALUE>Microsoft Operations Management Suite for UNIX/Linux agent</VALUE>
          </PROPERTY>
          <PROPERTY NAME="Size" TYPE="uint32">
            <VALUE>38487871</VALUE>
          </PROPERTY>
        </INSTANCE>
    }

    expectedHash = {
      "CollectionName"=> "omsagent",
      "Name"=> "omsagent",
      "Publisher"=> "MicrosoftPublisher",
      "CurrentVersion"=> "1.1.0",
      "Timestamp"=> "2016-03-18T22:11:05.000Z",
      "Architecture"=> "x86_64",
      "Size"=> "38487871"
    }

    instanceXML = ChangeTracking::strToXML(instanceXMLstr).root
    assert_equal("INSTANCE", instanceXML.name)
    assert_equal("MSFT_nxPackageResource", instanceXML.attributes['CLASSNAME'])
    instanceHash = ChangeTracking::packageXMLtoHash(instanceXML)
    assert_equal(expectedHash, instanceHash)
  end

  def test_fileInventoryXMLtoHash
    instanceXMLstr = %{
 <INSTANCE CLASSNAME="MSFT_nxFileInventoryResource">
     <PROPERTY NAME="Group" TYPE="string">
         <VALUE>root</VALUE>
     </PROPERTY>
     <PROPERTY NAME="Checksum" TYPE="string">
         <VALUE>1471727542</VALUE>
     </PROPERTY>
     <PROPERTY NAME="DestinationPath" TYPE="string">
         <VALUE>/etc/yum.conf</VALUE>
     </PROPERTY>
     <PROPERTY NAME="Mode" TYPE="string">
         <VALUE>644</VALUE>
     </PROPERTY>
     <PROPERTY NAME="CreatedDate" TYPE="datetime">
         <VALUE>20160820211222.000000+300</VALUE>
     </PROPERTY>
     <PROPERTY NAME="Owner" TYPE="string">
         <VALUE>root</VALUE>
     </PROPERTY>
     <PROPERTY NAME="Type" TYPE="string">
         <VALUE>file</VALUE>
     </PROPERTY>
     <PROPERTY NAME="ModifiedDate" TYPE="datetime">
         <VALUE>20160820211222.000000+300</VALUE>
     </PROPERTY>
     <PROPERTY NAME="Contents" TYPE="string">
         <VALUE></VALUE>
     </PROPERTY>
     <PROPERTY NAME="FileSize" TYPE="uint64">
         <VALUE>835</VALUE>
     </PROPERTY>
 </INSTANCE>
    }
    expectedHash = {
       "Checksum"=>"1471727542",
       "CollectionName"=>nil,
       "Contents"=>"",
       "CreatedDate"=>"20160820211222.000000+300",
       "DestinationPath"=>"/etc/yum.conf",
       "FileSize"=>"835",
       "Group"=>"root",
       "Mode"=>"644",
       "ModifiedDate"=>"20160820211222.000000+300",
       "Owner"=>"root",
       "Type"=>"file"
    }
    instanceXML = ChangeTracking::strToXML(instanceXMLstr).root
    assert_equal("INSTANCE", instanceXML.name)
    assert_equal("MSFT_nxFileInventoryResource", instanceXML.attributes['CLASSNAME'])
    instanceHash = ChangeTracking::serviceXMLtoHash(instanceXML)
    assert_equal(expectedHash, instanceHash)
  end

  def test_transform_and_wrap_Package
    expectedHash={"DataItems"=>
       [{"Collections"=>
         [{"Architecture"=>"x86_64",
           "CollectionName"=>"rsyslog",
           "CurrentVersion"=>"7.4.7",
           "Name"=>"rsyslog",
           "Publisher"=>"CentOS BuildSystem <http://bugs.centos.org>",
           "Size"=>"2033615",
           "Timestamp"=>"2015-10-19T16:13:03.000Z"}],
         "Computer"=>"HostName",
         "ConfigChangeType"=>"Software.Packages",
         "Timestamp"=>"2016-03-15T19:02:38.577Z"}],
       "DataType"=>"CONFIG_CHANGE_BLOB",
       "IPName"=>"changetracking"}
    expectedTime = Time.utc(2016,3,15,19,2,38.5776)
    wrappedHash = ChangeTracking::transform_and_wrap(@package_xml_str, "HostName", expectedTime, "oms.changetracking.package")
    assert_equal(expectedHash, wrappedHash)
  end

  def test_transform_and_wrap_Service
    expectedHash = {"DataItems"=>
       [{"Collections"=>
          [{"Architecture"=>"x86_64",
           "Arguments"=>"",
           "CollectionName"=>"omsagent",
           "Ensure"=>"present",
           "FilePath"=>"",
           "Installed"=>"true",
           "InstalledOn"=>"1458339065",
           "Name"=>"omsagent",
           "PackageDescription"=>
           "Microsoft Operations Management Suite for UNIX/Linux agent",
           "PackageGroup"=>"false",
           "PackageManager"=>"",
           "Publisher"=>"(none)",
           "ReturnCode"=>"0",
           "Size"=>"38487871",
           "Version"=>"1.1.0"}],
         "Computer"=>"HostName",
         "ConfigChangeType"=>"Daemons",
         "Timestamp"=>"2016-03-15T19:02:38.577Z"}],
       "DataType"=>"CONFIG_CHANGE_BLOB",
       "IPName"=>"changetracking"}
    expectedTime = Time.utc(2016,3,15,19,2,38.5776)
    wrappedHash = ChangeTracking::transform_and_wrap(@service_xml_str, "HostName", expectedTime, "oms.changetracking.service")
    assert_equal(expectedHash, wrappedHash)
  end

  def test_transform_and_wrap_file_inventory
    expectedHash = {"DataItems"=>
    [{"Collections"=>
       [{"CollectionName"=>"/etc/yum.conf",
         "Contents"=>"",
         "DateCreated"=>"2016-08-20T21:12:22.000Z",
         "DateModified"=>"2016-08-20T21:12:22.000Z",
         "FileSystemPath"=>"/etc/yum.conf",
         "Group"=>"root",
         "Mode"=>"644",
         "Owner"=>"root",
         "Size"=>"835"}],
      "Computer"=>"HostName",
      "ConfigChangeType"=>"Files",
      "Timestamp"=>"2016-03-15T19:02:38.577Z"}],
    "DataType"=>"CONFIG_CHANGE_BLOB",
    "IPName"=>"changetracking"}

    expectedTime = Time.utc(2016,3,15,19,2,38.5776)
    wrappedHash = ChangeTracking::transform_and_wrap(@fileInventory_xml_str,  "HostName", expectedTime, "oms.changetracking.file")
    assert_equal(expectedHash, wrappedHash, "#{wrappedHash}")
  end

  def test_performance_packagechangetracking
    inventoryXMLstr = File.read(@packageinventoryPath)

    start = Time.now
    expectedTime = Time.now
    transformedHash = ChangeTracking::transform(inventoryXMLstr)
    wrappedHash = ChangeTracking::wrap(transformedHash, "HostName",expectedTime)
    finish = Time.now
    time_spent = finish - start
    # Test that duplicates are removed as well. The test data has 1374 packages and 216 services with some duplicates.
    assert_equal(1371, wrappedHash["DataItems"][0]["Collections"].size, "Got the wrong number of package instances.")
    if time_spent > 1.0
      warn("Method transform_and_wrap too slow, it took #{time_spent.round(2)}s to complete.")
    end
  end

  def test_performance_servicechangetracking
    inventoryXMLstr = File.read(@serviceinventoryPath)

    start = Time.now
    expectedTime = Time.now
    transformedHash = ChangeTracking::transform(inventoryXMLstr)
    wrappedHash = ChangeTracking::wrap(transformedHash, "HostName",expectedTime)
    finish = Time.now
    time_spent = finish - start
    # Test that duplicates are removed as well. The test data has 1374 packages and 216 services with some duplicates.
    assert_equal(209, wrappedHash["DataItems"][0]["Collections"].size, "Got the wrong number of service instances.")
    if time_spent > 1.0
      warn("Method transform_and_wrap too slow, it took #{time_spent.round(2)}s to complete.")
    end
  end


  def test_performance_filechangetracking
    inventoryXMLstr = File.read(@fileinventoryPath)

    start = Time.now
    expectedTime = Time.now
    transformedHash = ChangeTracking::transform(inventoryXMLstr)
    wrappedHash = ChangeTracking::wrap(transformedHash, "HostName",expectedTime)
    finish = Time.now
    time_spent = finish - start
    # Test that duplicates are removed as well. The test data has 1374 packages and 216 services with some duplicates.
    assert_equal(1, wrappedHash["DataItems"][0]["Collections"].size, "Got the wrong number of file inventory instances")
    if time_spent > 1.0
      warn("Method transform_and_wrap too slow, it took #{time_spent.round(2)}s to complete.")
    end
  end

  def test_remove_duplicates_service
    inventoryXMLstr = File.read(@serviceinventoryPath)
    inventoryXML = ChangeTracking::strToXML(inventoryXMLstr)
    instancesXML = ChangeTracking::getInstancesXML(inventoryXML)
    servicesXML = instancesXML.select { |instanceXML| ChangeTracking::isServiceInstanceXML(instanceXML) }
    services = servicesXML.map { |service| ChangeTracking::serviceXMLtoHash(service)}

    assert_equal(216, services.size)

    collectionNames = services.map { |service| service["CollectionName"] }
    collectionNamesSet = Set.new collectionNames
    assert_equal(209, collectionNamesSet.size) # 7 duplicates
    assert(collectionNamesSet.size < collectionNames.size, "Test data does not contain duplicate Collection Names")

    data_items_dedup = ChangeTracking::removeDuplicateCollectionNames(services)
    assert_equal(collectionNamesSet.size, data_items_dedup.size, "Deduplication failed")
  end

  def test_remove_duplicates_file
    inventoryXMLstr = File.read(@fileinventoryPath)
    inventoryXML = ChangeTracking::strToXML(inventoryXMLstr)
    instancesXML = ChangeTracking::getInstancesXML(inventoryXML)
    servicesXML = instancesXML.select { |instanceXML| ChangeTracking::isServiceInstanceXML(instanceXML) }

    fileInventoriesXML = instancesXML.select { |instanceXML| ChangeTracking::isFileInventoryInstanceXML(instanceXML) }
    fileInventories = fileInventoriesXML.map { |fileInventory|  ChangeTracking::fileInventoryXMLtoHash(fileInventory)}
    assert_equal(2, fileInventories.size)

    fileInventoriesNames = fileInventories.map { |fileInventory| fileInventory["CollectionName"] }
    fileInventoriesNamesSet = Set.new fileInventoriesNames
    assert_equal(1, fileInventoriesNamesSet.size) # 1 duplicate
    assert(fileInventoriesNamesSet.size < fileInventoriesNames.size, "Test data does not contain duplicate Collection Names")

    file_items_dedup = ChangeTracking::removeDuplicateCollectionNames(fileInventories)
    assert_equal(fileInventoriesNamesSet.size, file_items_dedup.size, "Deduplication failed")
  end
end
